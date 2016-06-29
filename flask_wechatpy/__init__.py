#!/usr/bin/env python
# encoding: utf-8

import functools
from flask import request, current_app, abort, redirect
from wechatpy.replies import BaseReply
from wechatpy.pay import WeChatPay as ori_WeChatPay
from wechatpy.utils import check_signature
from wechatpy.exceptions import (
    InvalidSignatureException,
    InvalidAppIdException,
    WeChatOAuthException,
)


class Wechat(object):

    def __init__(self, app=None):

        self._wechat_client = None

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        config = app.config
        config.setdefault('WECHAT_APPID', None)
        config.setdefault('WECHAT_SECRET', None)
        config.setdefault('WECHAT_TYPE', 0)
        config.setdefault('WECHAT_SESSION_TYPE', None)
        config.setdefault('WECHAT_SESSION_PREFIX', 'flask-wechatpy')
        config.setdefault('WECHAT_AUTO_RETRY', True)
        config.setdefault('WECHAT_TIMEOUT', None)

        assert config['WECHAT_APPID'] is not None
        assert config['WECHAT_SECRET'] is not None

        if config['WECHAT_TYPE'] == 0:
            from wechatpy import WeChatClient
        else:
            from wechatpy.enterprise import WeChatClient

        if config['WECHAT_SESSION_TYPE'] == 'redis':
            from wechat.session.redisstorage import RedisStorage
            from redis import Redis
            if config.get('WECHAT_SESSION_REDIS_URL'):
                redis = Redis.from_url(config['WECHAT_SESSION_REDIS_URL'])
            else:
                redis = Redis(
                    host=config.get('WECHAT_SESSION_REDIS_HOST', 'localhost'),
                    port=config.get('WECHAT_SESSION_REDIS_PORT', 6379),
                    db=config.get('WECHAT_SESSION_REDIS_DB', 0),
                    password=config.get('WECHAT_SESSION_REDIS_PASS', None)
                )
            session_interface = RedisStorage(redis, prefix=config['WECHAT_SESSION_PREFIX'])
        elif config['WECHAT_SESSION_TYPE'] == 'memcached':
            from wechatpy.session.memcachedstorage import MemcachedStorage
            mc = self._get_mc_client(config['WECHAT_SESSION_MEMCACHED'])
            session_interface = MemcachedStorage(mc, prefix=config['WECHAT_SESSION_PREFIX'])
        elif config['WECHAT_SESSION_TYPE'] == 'shove':
            pass
        else:
            session_interface = None

        self._wechat_client = WeChatClient(
            config['WECHAT_APPID'],
            config['WECHAT_SECRET'],
            session=session_interface,
            timeout=config['WECHAT_TIMEOUT'],
            auto_retry=config['WECHAT_AUTO_RETRY'],
        )

        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['wechatpy'] = self

    def __getattr__(self, name):
        return getattr(self._wechat_client, name)

    def _get_mc_client(self, servers):
        try:
            import pylibmc
        except ImportError:
            pass
        else:
            return pylibmc.Client(servers)

        try:
            import memcache
        except ImportError:
            pass
        else:
            return memcache.Client(servers)


def wechat_required(method):

    @functools.wraps(method)
    def wrapper(*args, **kwargs):
        if current_app.config['WECHAT_TYPE'] == 0:
            res = _wechat_required(method, *args, **kwargs)
        else:
            res = _enterprise_wechat_required(method, *args, **kwargs)

        return res

    return wrapper


def _wechat_required(method, *args, **kwargs):
    from wechatpy.crypto import WeChatCrypto
    from wechatpy import parse_message

    signature = request.args.get('signature')

    timestamp = request.args.get('timestamp')
    nonce = request.args.get('nonce')

    if not current_app.config.get('WECHAT_TOKEN'):
        return abort(500, "Token is None")

    token = current_app.config['WECHAT_TOKEN']
    try:
        check_signature(token, signature, timestamp, nonce)
    except InvalidSignatureException:
        current_app.logger.warning('check signature failed.')
        return abort(403)

    if request.method == 'GET':
        return request.args.get('echostr', '')

    raw_msg = request.data
    current_app.logger.debug(raw_msg)
    if current_app.config.get('WECHAT_AES_KEY'):
        crypto = WeChatCrypto(
            current_app.config['WECHAT_TOKEN'],
            current_app['WECHAT_AES_KEY'],
            current_app.config['WECHAT_APPID']
        )
        try:
            raw_msg = crypto.decrypt_message(
                raw_msg,
                signature,
                timestamp,
                nonce
            )
        except (InvalidAppIdException, InvalidSignatureException):
            current_app.logger.warning('decode message failed.')
            return abort(403)

    request.wechat_msg = parse_message(raw_msg)

    res = method(*args, **kwargs)
    xml = ''

    if isinstance(res, BaseReply):
        xml = res.render()

    if current_app.config.get('WECHAT_AES_KEY'):
        crypto = WeChatCrypto(
            current_app.config['WECHAT_TOKEN'],
            current_app.config['WECHAT_AES_KEY'],
            current_app.config['WECHAT_APPID']
        )
        xml = crypto.encrypt_message(xml, nonce, timestamp)

    return xml


def _enterprise_wechat_required(method, *args, **kwargs):
    from wechatpy.enterprise import parse_message
    from wechatpy.enterprise.crypto import WeChatCrypto
    from wechatpy.enterprise.exceptions import InvalidCorpIdException
    signature = request.args.get('msg_signature')
    timestamp = request.args.get('timestamp')
    nonce = request.args.get('nonce')

    if not current_app.config.get('WECHAT_TOKEN'):
        return abort(500, "Token is None")

    crypto = WeChatCrypto(
        current_app.config['WECHAT_TOKEN'],
        current_app['WECHAT_AES_KEY'],
        current_app.config['WECHAT_APPID']
    )
    if request.method == 'GET':
        echo_str = request.args.get('echostr')
        try:
            echo_str = crypto.check_signature(
                signature,
                timestamp,
                nonce,
                echo_str
            )
        except InvalidSignatureException:
            abort(403)
        return echo_str

    try:
        msg = crypto.decrypt_message(
            request.data,
            signature,
            timestamp,
            nonce,
        )
    except (InvalidSignatureException, InvalidCorpIdException):
        return abort(403)
    else:
        request.wechat_msg = parse_message(msg)

    res = method(*args, **kwargs)
    xml = ''

    if isinstance(res, BaseReply):
        xml = res.render()

    crypto = WeChatCrypto(
        current_app.config['WECHAT_TOKEN'],
        current_app.config['WECHAT_AES_KEY'],
        current_app.config['WECHAT_APPID']
    )
    xml = crypto.encrypt_message(xml, nonce, timestamp)

    return xml


def _check_user():
    from flask import session
    return session.get('wechat_user_id')


def _set_user(user_info):
    from flask import session
    session['wechat_user_id'] = user_info['openid']


def oauth(check_func=_check_user, set_user=_set_user, scope='snsapi_base', state=None):
    def decorater(method):
        @functools.wraps(method)
        def wrapper(*args, **kwargs):
            from wechatpy.oauth import WeChatOAuth
            if callable(state):
                _state = state()
            else:
                _state = state or ''
            redirect_uri = current_app.config.get('WECHAT_OAUTH_URI')
            if not redirect_uri:
                redirect_uri = request.url
            wechat_oauth = WeChatOAuth(
                current_app.config['WECHAT_APPID'],
                current_app.config['WECHAT_SECRET'],
                redirect_uri,
                scope,
                _state
            )
            user = check_func()
            if request.args.get('code') and not user:
                try:
                    res = wechat_oauth.fetch_access_token(request.args['code'])
                except WeChatOAuthException:
                    return abort(403)
                else:
                    if scope == 'snsapi_base':
                        set_user(res)
                    else:
                        user_info = wechat_oauth.get_user_info()
                        set_user(user_info)
            elif not user:
                return redirect(wechat_oauth.authorize_url)
            return method(*args, **kwargs)
        return wrapper
    return decorater


class WechatPay(object):

    def __init__(self, app=None):

        self._wechat_client = None

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        config = app.config
        config.setdefault('WECHAT_APPID', None)
        config.setdefault('WECHAT_PAY_API_KEY', None)
        config.setdefault('WECHAT_PAY_MCH_CERT', None)
        config.setdefault('WECHAT_PAY_MCH_KEY', None)
        config.setdefault('WECHAT_PAY_MCH_ID', None)
        config.setdefault('WECHAT_PAY_SUB_MCH_ID', None)

        assert config['WECHAT_APPID'] is not None
        assert config['WECHAT_PAY_API_KEY'] is not None
        assert config['WECHAT_PAY_MCH_CERT'] is not None
        assert config['WECHAT_PAY_MCH_KEY'] is not None
        assert config['WECHAT_PAY_MCH_ID'] is not None

        self._wechat_pay = ori_WeChatPay(
            appid=config['WECHAT_APPID'],
            api_key=config['WECHAT_PAY_API_KEY'],
            mch_id=config['WECHAT_PAY_MCH_ID'],
            sub_mch_id=config.get('WECHAT_PAY_SUB_MCH_ID', None),
            mch_cert=config['WECHAT_PAY_MCH_CERT'],
            mch_key=config['WECHAT_PAY_MCH_KEY'],
        )
        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['wechat_pay'] = self

    def __getattr__(self, name):
        return getattr(self._wechat_pay, name)
