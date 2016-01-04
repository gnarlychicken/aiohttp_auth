from .ticket_auth import TktAuthentication


COOKIE_AUTH_KEY = 'aiohttp_auth.auth.CookieTktAuthentication'


class CookieTktAuthentication(TktAuthentication):
    """Ticket authentication mechanism based on the ticket_auth library, with
    ticket data being stored as a cookie in the request.
    """

    async def remember_ticket(self, request, ticket):
        """Called to store and remember the ticket data for a request"""
        request[COOKIE_AUTH_KEY] = ticket

    async def forget_ticket(self, request):
        """Called to forget the ticket data for a request"""
        request[COOKIE_AUTH_KEY] = ''

    async def get_ticket(self, request):
        """Returns the ticket for a request, or None if the request does not
        contain a ticket
        """
        return request.cookies.get(self.cookie_name, None)

    async def process_response(self, request, response):
        """Called to perform any processing of the response required (setting
        cookie data, etc).
        """
        if COOKIE_AUTH_KEY in request:
            if response.started:
                raise RuntimeError("Cannot save cookie into started response")

            cookie = request[COOKIE_AUTH_KEY]
            if cookie == '':
                response.del_cookie(self.cookie_name)
            else:
                response.set_cookie(self.cookie_name, cookie)
