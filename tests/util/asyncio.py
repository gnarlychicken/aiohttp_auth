import asyncio
from functools import wraps


def run_until_complete(loop=None):
    """Returns a decorator that runs the function passed in an async event
    loop, using the supplied event loop.

    If no loop is supllied, loop is set to asyncio.get_event_loop. This
    decorator is useful when writing unit tests, allowing asyncrhonous tests
    to be run like a normal function
    """
    if loop is None:
        loop = asyncio.get_event_loop()

    def decorator(func):

        @wraps(func)
        def wrapper(*args, **kwargs):
            return loop.run_until_complete(func(*args, **kwargs))

        return wrapper

    return decorator