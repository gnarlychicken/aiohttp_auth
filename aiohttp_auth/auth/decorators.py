from functools import wraps
from aiohttp import web
from .auth import get_auth


def auth_required(func):
    """Utility decorator that checks if a user has been authenticated for this
    request, and raises HTTPForbidden if not
    """
    @wraps(func)
    async def wrapper(*args):
        if (await get_auth(args[-1])) is None:
            raise web.HTTPForbidden()

        return await func(*args)

    return wrapper

