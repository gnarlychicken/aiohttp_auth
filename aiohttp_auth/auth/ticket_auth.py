import time
from ipaddress import ip_address
from ticket_auth import TicketFactory, TicketError
from aiohttp_session import get_session
from .abstract_auth import AbstractAuthentication


class AuthTktAuthentication(AbstractAuthentication):
    """Ticket authentication mechanism based on mod_auth"""

    def __init__(self, secret, max_age, include_ip=False, cookie_name='AUTH_TKT'):
        """Initializes the ticket authentication mechanism."""
        self._ticket = TicketFactory(secret)
        self._max_age = max_age
        self._include_ip = include_ip
        self._cookie_name = cookie_name

    @property
    def cookie_name(self):
        """Returns the name of the cookie stored in the session"""
        return self._cookie_name

    async def remember(self, request, user_id):
        """Called to store and remember the userid for a request"""
        ip = self._get_ip(request)
        valid_until = int(time.time()) + self._max_age
        ticket = self._ticket.new(user_id, valid_until=valid_until, client_ip=ip)

        session = await get_session(request)
        session[self._cookie_name] = ticket

    async def forget(self, request):
        """Called to forget the userid fro a request"""
        session = await get_session(request)
        session.pop(self._cookie_name, '')

    async def get(self, request):
        """Returns the userid for a request, or None if the request is not
        authenticated
        """
        session = await get_session(request)
        try:
            ticket = session.get(self._cookie_name)
            if ticket is None:
                return None

            # Returns a tuple of (user_id, token, userdata, validuntil)
            fields = self._ticket.validate(ticket, self._get_ip(request))
            return fields.user_id

        except TicketError as e:
            return None

    def _get_ip(self, request):
        ip = None
        if self._include_ip:
            peername = request.transport.get_extra_info('peername')
            if peername:
                ip = ip_address(peername[0])

        return ip
