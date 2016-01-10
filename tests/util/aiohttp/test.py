import asyncio
from aiohttp import web, protocol
from aiohttp.multidict import CIMultiDict
from aiohttp.streams import EmptyStreamReader
from http.cookies import SimpleCookie


async def _identity(request):
    return web.Response()


async def prepare_request(request, middlewares):
    """Mainly used in testing, passes the request through the middlewares to
    much like the aiohttp application does, to shortcut the need for a aiohttp
    application object when testing
    """
    handler = _identity
    for factory in reversed(middlewares):
        handler = await factory(None, handler)
    response = await handler(request)

    return request


async def make_request(method, path, middlewares, cookies=None):
    headers = CIMultiDict()
    if cookies:
        for key, value in cookies:
            headers.add('Cookie', _cookie_value(key, value))

    message = protocol.RawRequestMessage(method, path, protocol.HttpVersion11,
                                         headers, True, False)
    request = web.Request({}, message, EmptyStreamReader(), None, None, None)

    if middlewares:
        return await prepare_request(request, middlewares)

    return request


async def make_response(request, middlewares):
    handler = _identity
    for factory in reversed(middlewares):
        handler = await factory(None, handler)

    return await handler(request)


def make_auth_session(secret, user_id, cookie_name):
    from ticket_auth import TicketFactory
    import time
    json = {}
    tf = TicketFactory(secret)
    ticket = tf.new(user_id)
    json['created'] = int(time.time())
    json['session'] = { cookie_name: ticket }
    return json


def _cookie_value(key, value):
    m = SimpleCookie()
    m[key] = value
    return m.output(header='')