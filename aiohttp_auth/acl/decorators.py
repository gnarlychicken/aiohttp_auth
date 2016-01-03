from functools import wraps
from aiohttp import web
from .acl import get_permitted


def acl_required(permission, context):
    """Returns a decorator that checks if a user has the requested permission
    from the passed acl context. Raises HTTPForbidden if not.

    The context parameter is either a sequence of acl
    tuples, or a callable that returns a sequence of acl tuples.
    """

    def decorator(func):

        @wraps(func)
        async def wrapper(*args):
            request = args[-1]

            if callable(context):
                context = context()

            if await get_permitted(request, permission, context):
                return await func(*args)

            raise web.HTTPForbidden()

        return wrapper

    return decorator

