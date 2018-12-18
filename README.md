# Flask-Wechatpy

Flask 的 [wechatpy](http://wechatpy.readthedocs.org) 扩展


# Configuration

配置 | 默认值 | 说明
------------ | ------------- | ------------
WECHAT_APPID | None | 微信 APPID，如果是企业号则是 CORPID
WECHAT_SECRET | None | 微信 SECRET
WECHAT_TYPE | 0 | wechatpy client 类型，0 为公众号（订阅号和服务号），1 为企业号
WECHAT_SESSION_TYPE | None | wechatpy session 类型，可选 redis，memcached，默认为 memory
WECHAT_SESSION_PREFIX | flask-wechatpy | wechatpy session prefix
WECHAT_AUTO_RETRY | True | wechatpy 异常时自动重试
WECHAT_TIMEOUT | None | wechatpy 异常时自动重试
WECHAT_SESSION_REDIS_URL | None | eg. redis://localhost:6379/0
WECHAT_SESSION_MEMCACHED | None | eg. 127.0.0.1:11211
WECHAT_AES_KEY | None | 微信消息加密的 key，如果是企业号则必填
WECHAT_TOKEN | None | 微信接收消息时的 token
WECHAT_OAUTH_URI | None | oauth 时的回调地址，默认为当前 url
WECHAT_PAY_API_KEY | None | 微信支付 api key
WECHAT_PAY_MCH_CERT | None | 微信支付 商户证书路径 eg. apiclient_cert.pem
WECHAT_PAY_MCH_KEY | None | 微信支付 商户密钥路径 eg. apiclient_key.pem
WECHAT_PAY_MCH_ID | None | 微信支付 商户号
WECHAT_PAY_SUB_MCH_ID | None | 微信支付 子商户号，非必填
WECHAT_OPEN_APP_ID | None | 微信开放平台 APP ID
WECHAT_OPEN_APP_SECRET | None | 微信开放平台 APP SECRET

# Usage

see [demo.py](demo.py)

## OAuth

默认使用 flask session 储存 oauth 验证后的 openid（企业号则为 user_id）

`oauth` 支持 4 个参数
* `check_func`: callable，如果返回 `None` 或者 `False` 时，将进行微信 OAuth
* `set_user`: callable，微信回调回来后，会调用 `set_user`，并且 `set_user`，接收一个参数，用户信息
* `scope`: snsapi_base 或者 snsapi_userinfo，当 scope 为 snsapi_userinfo 时，`set_user` 的参数会是用户信息，包含头像等信息
* `state`: 可以是一个函数，默认为 None，用来验证请求

## wechat_required

微信回调模式下的`router`辅助的 decorator，当验证通过后，可以通过`request.wechat_msg`获取发来的消息，并且可以直接在`router`里返回`BaseReply`类型的回复类型
