import unittest
import json
from aiohttp import web
from aiohttp_auth import auth, auth_middleware
from aiohttp_auth import acl, acl_middleware
from aiohttp_auth.permissions import Group, Permission
from aiohttp_session import session_middleware, SimpleCookieStorage
from .util import asyncio
from .util.aiohttp.test import (
    make_request,
    make_response,
    make_auth_session)


class ACLMiddlewareTests(unittest.TestCase):
    # Secret used in all the tests
    SECRET = b'01234567890abcdef'

    def setUp(self):
        """Creates the storage and middlewares objects"""
        self.storage = SimpleCookieStorage()
        self.auth = auth.AuthTktAuthentication(
            self.SECRET, 15, cookie_name='auth')

    @asyncio.run_until_complete()
    async def test_no_middleware_installed(self):
        session_data = make_auth_session(
            self.SECRET, 'some_user', self.auth.cookie_name)

        request = await make_request('GET', '/', self._middleware(None), \
            [(self.storage.cookie_name, json.dumps(session_data))])

        with self.assertRaises(RuntimeError):
            groups = await acl.get_user_groups(request)

    @asyncio.run_until_complete()
    async def test_correct_groups_returned_for_authenticated_user(self):
        session_data = make_auth_session(
            self.SECRET, 'some_user', self.auth.cookie_name)

        request = await make_request('GET', '/', \
            self._middleware(self._groups_callback), \
            [(self.storage.cookie_name, json.dumps(session_data))])

        groups = await acl.get_user_groups(request)
        self.assertIn('group0', groups)
        self.assertIn('group1', groups)
        self.assertIn('some_user', groups)
        self.assertIn(Group.Everyone, groups)
        self.assertIn(Group.AuthenticatedUser, groups)

    @asyncio.run_until_complete()
    async def test_correct_groups_returned_for_unauthenticated_user(self):
        request = await make_request('GET', '/', \
            self._middleware(self._groups_callback))

        groups = await acl.get_user_groups(request)
        self.assertIn('group0', groups)
        self.assertIn('group1', groups)
        self.assertNotIn('some_user', groups)
        self.assertNotIn(None, groups)
        self.assertIn(Group.Everyone, groups)
        self.assertNotIn(Group.AuthenticatedUser, groups)

    @asyncio.run_until_complete()
    async def test_forbidden_thrown_if_none_returned_from_callback(self):
        request = await make_request('GET', '/', \
            self._middleware(self._none_groups_callback))

        with self.assertRaises(web.HTTPForbidden):
            await acl.get_user_groups(request)

    @asyncio.run_until_complete()
    async def test_acl_permissions(self):
        request = await make_request('GET', '/', \
            self._middleware(self._groups_callback))

        context = [(Permission.Allow, 'group0', ('test0',)),
                   (Permission.Deny, 'group1', ('test1',)),
                   (Permission.Allow, Group.Everyone, ('test1',)),]

        self.assertTrue(await acl.get_permitted(request, 'test0', context))
        self.assertFalse(await acl.get_permitted(request, 'test1', context))

    @asyncio.run_until_complete()
    async def test_permission_order(self):
        session_data = make_auth_session(
            self.SECRET, 'some_user', self.auth.cookie_name)

        request0 = await make_request('GET', '/', \
            self._middleware(self._auth_groups_callback), \
            [(self.storage.cookie_name, json.dumps(session_data))])

        request1 = await make_request('GET', '/', \
            self._middleware(self._auth_groups_callback))

        context = [(Permission.Allow, Group.Everyone, ('test0',)),
                   (Permission.Deny, 'group1', ('test1',)),
                   (Permission.Allow, Group.Everyone, ('test1',)),]

        self.assertTrue(await acl.get_permitted(request0, 'test0', context))
        self.assertTrue(await acl.get_permitted(request1, 'test0', context))

        self.assertFalse(await acl.get_permitted(request0, 'test1', context))
        self.assertTrue(await acl.get_permitted(request1, 'test1', context))

    async def _groups_callback(self, user_id):
        """Groups callback function that always returns two groups"""
        return ('group0', 'group1')

    async def _auth_groups_callback(self, user_id):
        """Groups callback function that always returns two groups"""
        if user_id:
            return ('group0', 'group1')

        return ()

    async def _none_groups_callback(self, user_id):
        """Groups callback function that always returns None"""
        return None

    def _middleware(self, acl_callback):
        """Returns the middlewares used in the test"""
        if acl_callback:
            return [
                session_middleware(self.storage),
                auth_middleware(self.auth),
                acl_middleware(acl_callback)]

        return [
            session_middleware(self.storage),
            auth_middleware(self.auth)]
