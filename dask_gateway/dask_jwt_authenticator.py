import functools
import contextvars
import os

import asyncio
import aiohttp
import jwt

from aiohttp import web
from traitlets import Dict, Unicode, default
from traitlets.config import LoggingConfigurable

from dask_gateway_server.auth import Authenticator, unauthorized, User


class JwtAuthenticator(Authenticator, LoggingConfigurable):

    jwks_url = Unicode(
        help="""
        The JWKS URL to get the public keys to verify JWT.

        By default this is determined from the ``JWKS_URL``
        environment variable.
        """,
        config=True,
    )

    @default("jwks_url")
    def _default_jwks_url(self):
        out = os.environ.get("JWKS_URL")
        if not out:
            raise ValueError("JWKS_URL must be set")
        return out

    #jwks_url = "https://identity.data.destination-earth.eu/auth/realms/dedl/protocol/openid-connect/certs"  # json

    # Known Dask roles, order is important, from high to low
    profiles = Dict()
    @default("profiles")
    def _default_profiles(self):
        return {
            "stack-dask-high": {
                "worker_cores": 12,
                "worker_memory": 24,
            },
            "stack-dask-medium": {
                "worker_cores": 4,
                "worker_memory": 8,
            },
            "stack-dask-low":{
                "worker_cores": 1,
                "worker_memory": 2,
            }
        }

    async def setup(self, app):
        self.dask_roles = set(self.profiles.copy().keys())
        self.session = aiohttp.ClientSession()
        self._jwks_client = jwt.PyJWKClient(self.jwks_url)

    # Maybe premature optimization... get_signing_key_from_jwt is blocking call,
    # so wrap it around a thread, maybe.
    async def _wrapped_get_signing_key_from_jwt(self, token):
        # no asyncio.to_thread in 3.8 :(
        loop = asyncio.get_event_loop()
        ctx = contextvars.copy_context()
        func = self._jwks_client.get_signing_key_from_jwt
        func_call = functools.partial(ctx.run, func, token)
        signing_key = await loop.run_in_executor(None, func_call)
        return signing_key

    def validate(self, signing_key, token):
        return jwt.decode(token, signing_key.key,
            audience="account", algorithms=["RS256"])

    async def cleanup(self):
        if hasattr(self, "session"):
            await self.session.close()

    async def authenticate(self, request):
        auth_headers = request.headers.get("Authorization")
        if not auth_headers:
            raise web.HTTPUnauthorized(reason="No JWT in Headers.")

        # not happy with this, but :shrug:
        try:
            idx = auth_headers.index("Bearer ")
        except ValueError:
            raise web.HTTPUnauthorized(reason="No 'Bearer' in Authorization header.")
        token = auth_headers[idx + 7 :]  # len("Bearer ") == 7

        signing_key = await self._wrapped_get_signing_key_from_jwt(token)
        try:
            data = self.validate(signing_key, token)
        except jwt.exceptions.ExpiredSignatureError as e:
            self.log.debug("JWT: Expired Key")
            raise unauthorized("expired jwt")

        if data and \
            ("realm_access" in data and "preferred_username" in data) and \
                "roles" in data["realm_access"]:
            user_name = data["preferred_username"]
            roles = set(data["realm_access"]["roles"])
            user_dask_role = sorted(roles.intersection(self.dask_roles))
            if len(user_dask_role) == 0:
                self.log.error(f"Service access for user {user_name} declined.")
                raise unauthorized("jwt")
            else:
                self.log.info(f"User {user_name} access granted with role {user_dask_role[0]}.")
                return User(
                    user_name,
                    groups=[user_dask_role[0]],
                    admin=False,
                )
        else:
            self.log.error("JWT: No data in token validation.")
            raise unauthorized("jwt")
