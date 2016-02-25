import unittest
import json
import time
from os import urandom
from aiohttp_auth import auth, auth_middleware
from aiohttp_session import session_middleware, SimpleCookieStorage
from aiohttp import web
from ticket_auth import TicketFactory
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
            auth_middleware(auth.SessionTktAuthentication(urandom(16), 15))]

        request = await make_request('GET', '/', middlewares)
        user_id = await auth.get_auth(request)
        self.assertIsNone(user_id)

    @asyncio.run_until_complete()
    async def test_middleware_stores_auth_in_session(self):
        secret = b'01234567890abcdef'
        storage = SimpleCookieStorage()
        auth_ = auth.SessionTktAuthentication(secret, 15, cookie_name='auth')
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
        auth_ = auth.SessionTktAuthentication(secret, 15, cookie_name='auth')
        middlewares = [
            session_middleware(storage),
            auth_middleware(auth_)]

        session_data = make_auth_session(secret, 'some_user', auth_.cookie_name)
        request = await make_request('GET', '/', middlewares, \
            [(storage.cookie_name, json.dumps(session_data))])

        user_id = await auth.get_auth(request)
        self.assertEqual(user_id, 'some_user')

    @asyncio.run_until_complete()
    async def test_middleware_stores_auth_in_cookie(self):
        secret = b'01234567890abcdef'
        auth_ = auth.CookieTktAuthentication(secret, 15, cookie_name='auth')
        middlewares = [
            auth_middleware(auth_)]

        request = await make_request('GET', '/', middlewares)
        await auth.remember(request, 'some_user')
        response = await make_response(request, middlewares)
        self.assertTrue(auth_.cookie_name in response.cookies)

    @asyncio.run_until_complete()
    async def test_middleware_gets_auth_from_cookie(self):
        secret = b'01234567890abcdef'
        auth_ = auth.CookieTktAuthentication(secret, 15, 2, cookie_name='auth')
        middlewares = [
            auth_middleware(auth_)]

        session_data = TicketFactory(secret).new('some_user')
        request = await make_request('GET', '/', middlewares, \
            [(auth_.cookie_name, session_data)])

        user_id = await auth.get_auth(request)
        self.assertEqual(user_id, 'some_user')

        response = await make_response(request, middlewares)
        self.assertFalse(auth_.cookie_name in response.cookies)

    @asyncio.run_until_complete()
    async def test_middleware_reissues_ticket_auth(self):
        secret = b'01234567890abcdef'
        auth_ = auth.CookieTktAuthentication(secret, 15, 0, cookie_name='auth')
        middlewares = [
            auth_middleware(auth_)]

        valid_until = time.time() + 15
        session_data = TicketFactory(secret).new('some_user',
                                                 valid_until=valid_until)
        request = await make_request('GET', '/', middlewares, \
            [(auth_.cookie_name, session_data)])

        user_id = await auth.get_auth(request)
        self.assertEqual(user_id, 'some_user')

        response = await make_response(request, middlewares)
        self.assertTrue(auth_.cookie_name in response.cookies)
        self.assertNotEqual(response.cookies[auth_.cookie_name],
                          session_data)

    @asyncio.run_until_complete()
    async def test_middleware_doesnt_reissue_on_bad_response(self):
        secret = b'01234567890abcdef'
        auth_ = auth.CookieTktAuthentication(secret, 15, 0, cookie_name='auth')
        middlewares = [
            auth_middleware(auth_)]

        valid_until = time.time() + 15
        session_data = TicketFactory(secret).new('some_user',
                                                 valid_until=valid_until)
        request = await make_request('GET', '/', middlewares, \
            [(auth_.cookie_name, session_data)])

        user_id = await auth.get_auth(request)
        self.assertEqual(user_id, 'some_user')

        response = await make_response(request, middlewares, web.Response(status=400))
        self.assertFalse(auth_.cookie_name in response.cookies)
