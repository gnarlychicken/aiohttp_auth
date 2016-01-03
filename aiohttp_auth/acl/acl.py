import itertools
from aiohttp import web
from ..auth import get_auth
from ..permissions import Permission, Group


GROUPS_KEY = 'aiohttp_auth.acl.callback'


def acl_middleware(callback):
    """Returns a aiohttp_auth.acl middleware factory for use by the aiohttp
    application object.

    The function takes a callback function, which takes a user_id (as
    returned from the auth.get_auth function, and expects a sequence of
    permitted acl groups to be returned. This can be a empty tuple to
    represent no explicit permissions, or None to explicitly forbid this
    particular user_id (which may be None if no user exists)

    The callback function can be
    """
    async def _acl_middleware_factory(app, handler):

        async def _middleware_handler(request):
            # Save the policy in the request
            request[GROUPS_KEY] = callback

            # Call the next handler in the chain
            return await handler(request)

        return _middleware_handler

    return _acl_middleware_factory


async def get_user_groups(request):
    """Returns the groups that this particular user request has access to. This
    function gets the user id from the auth.get_auth function, and passes it to
    the acl callback function to get the groups.

    If the callback returns None, HTTPForbidden is raised.

    This function returns the sequence of group permissions provided by the
    callback, plus the Everyone group. If user_id is not None, the
    AuthnticatedUser group and the user_id are added to the groups returned by
    the function
    """
    acl_callback = request.get(GROUPS_KEY)
    if acl_callback is None:
        raise RuntimeError('acl_middleware not installed')

    user_id = await get_auth(request)
    groups = await acl_callback(user_id)
    if groups is None:
        raise web.HTTPForbidden()

    user_groups = (Group.AuthenticatedUser, user_id) if user_id is not None else ()

    return set(itertools.chain(groups, (Group.Everyone,), user_groups))


async def get_permitted(request, permission, context):
    """Returns true if the one of the groups in the request has the requested
    permission.
    """

    groups = await get_user_groups(request)
    for action, group, permissions in context:
        if group in groups:
            if permission in permissions:
                return action == Permission.Allow

    return False
