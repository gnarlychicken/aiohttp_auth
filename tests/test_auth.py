import unittest
import json
from os import urandom
from aiohttp_auth import auth, auth_middleware
from aiohttp_session import session_middleware, SimpleCookieStorage
from .util import asyncio
from .util.aiohttp.test import (
    make_request,
    make_response,
    make_auth_session)


class AuthMiddlewareTests(unittest.TestCase):

    @asyncio.run_until_complete()
    async def test_no_middleware_installed(self):
        middlewares = [
            session_middleware(SimpleCookieStorage()),]

        request = await make_request('GET', '/', middlewares)

        with self.assertRaises(RuntimeError):
            await auth.get_auth(request)

    @asyncio.run_until_complete()
    async def test_middleware_installed_no_session(self):
        middlewares = [
            session_middleware(SimpleCookieStorage()),
            auth_middleware(auth.AuthTktAuthentication(urandom(16), 15))]

        request = await make_request('GET', '/', middlewares)
        user_id = await auth.get_auth(request)
        self.assertIsNone(user_id)

    @asyncio.run_until_complete()
    async def test_middleware_stores_auth(self):
        secret = b'01234567890abcdef'
        storage = SimpleCookieStorage()
        auth_ = auth.AuthTktAuthentication(secret, 15, cookie_name='auth')
        middlewares = [
            session_middleware(storage),
            auth_middleware(auth_)]

        request = await make_request('GET', '/', middlewares)
        await auth.remember(request, 'some_user')
        response = await make_response(request, middlewares)
        self.assertTrue(auth_.cookie_name in \
            response.cookies.get(storage.cookie_name).value)

    @asyncio.run_until_complete()
    async def test_middleware_gets_auth_from_session(self):
        secret = b'01234567890abcdef'
        storage = SimpleCookieStorage()
        auth_ = auth.AuthTktAuthentication(secret, 15, cookie_name='auth')
        middlewares = [
            session_middleware(storage),
            auth_middleware(auth_)]

        session_data = make_auth_session(secret, 'some_user', auth_.cookie_name)
        request = await make_request('GET', '/', middlewares, \
            [(storage.cookie_name, json.dumps(session_data))])

        user_id = await auth.get_auth(request)
        self.assertEqual(user_id, 'some_user')

