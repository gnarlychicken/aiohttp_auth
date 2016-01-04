aiohttp_auth
============

This library provides authorization and authentication middleware plugins for
aiohttp servers.

These plugins are designed to be lightweight, simple, and extensible, allowing
the library to be reused regardless of the backend authentication mechanism.
This provides a familiar framework across projects.

There are two middleware plugins provided by the library. The auth_middleware
plugin provides a simple system for authenticating a users credentials, and
ensuring that the user is who they say they are.

The acl_middleware plugin provides a simple access control list authorization
mechanism, where users are provided access to different view handlers depending
on what groups the user is a member of.


auth_middleware Usage
---------------------



acl_middleware Usage
---------------------



License
-------

The library is licensed under a MIT license.
