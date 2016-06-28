#!/usr/bin/env python
# encoding: utf-8

from flask import Flask, request, session
from flask_wechatpy import Wechat, wechat_required, oauth
from wechatpy.replies import TextReply
from wechatpy.replies import create_reply


app = Flask(__name__)
app.config['WECHAT_APPID'] = 'wx186958a84617e867'
app.config['WECHAT_SECRET'] = '12e75aabd90ab2e034941f61f0c8d0aa'
app.config['WECHAT_TOKEN'] = 'token'
app.config['DEBUG'] = True
app.secret_key = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'

wechat = Wechat(app)


@app.route('/')
@oauth(scope='snsapi_userinfo')
def index():
    return "hello"


@app.route('/clear')
def clear():
    if 'wechat_user_id' in session:
        session.pop('wechat_user_id')
    return "ok"


@app.route('/wechat', methods=['GET', 'POST'])
@wechat_required
def wechat_handler():
    msg = request.wechat_msg
    if msg.type == 'text':
        reply = create_reply(msg.content, message=msg)
    else:
        reply = TextReply(content='hello', message=msg)

    return reply


@app.route('/access_token')
def access_token():
    return "access token: {}".format(wechat.access_token)

if __name__ == '__main__':
    app.run()
