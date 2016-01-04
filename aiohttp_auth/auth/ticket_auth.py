import abc
import time
from ipaddress import ip_address
from ticket_auth import TicketFactory, TicketError
from .abstract_auth import AbstractAuthentication


class TktAuthentication(AbstractAuthentication):
    """Ticket authentication mechanism based on the ticket_auth library.

    This class is an abstract class that creates a ticket and validates it.
    Storage of the ticket data itself is abstracted to allow different
    implementations to store the cookie differently (encrypted, server side
    etc).
    """

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

        await self.remember_ticket(request, ticket)

    async def forget(self, request):
        """Called to forget the userid for a request"""
        await self.forget_ticket(request)

    async def get(self, request):
        """Returns the userid for a request, or None if the request is not
        authenticated
        """
        ticket = await self.get_ticket(request)
        if ticket is None:
            return None

        try:
            # Returns a tuple of (user_id, token, userdata, validuntil)
            fields = self._ticket.validate(ticket, self._get_ip(request))
            return fields.user_id

        except TicketError as e:
            return None

    @abc.abstractmethod
    async def remember_ticket(self, request, ticket):
        """Called to store and remember the ticket data for a request"""
        pass

    @abc.abstractmethod
    async def forget_ticket(self, request):
        """Called to forget the ticket data for a request"""
        pass

    @abc.abstractmethod
    async def get_ticket(self, request):
        """Returns the ticket for a request, or None if the request does not
        contain a ticket
        """
        pass

    def _get_ip(self, request):
        ip = None
        if self._include_ip:
            peername = request.transport.get_extra_info('peername')
            if peername:
                ip = ip_address(peername[0])

        return ip
