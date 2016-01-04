import abc

class AbstractAuthentication(object):
    """Abstract authentication class"""

    @abc.abstractmethod
    async def remember(self, request, user_id):
        """Called to store and remember the userid for a request"""
        pass

    @abc.abstractmethod
    async def forget(self, request):
        """Called to forget the userid for a request"""
        pass

    @abc.abstractmethod
    async def get(self, request):
        """Returns the userid for a request, or None if the request is not
        authenticated
        """
        pass

    async def process_response(self, request, response):
        """Called to perform any processing of the response required (setting
        cookie data, etc).

        Default implementation does nothing.
        """
        pass