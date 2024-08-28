import asyncio
from aiohttp import web,ClientSession
from aioredis import create_redis_pool
import re
import time

class ReverseProxy:
    def __init__(self,backend_servers):
        self.backend_servers = backend_servers
        self.server_index = 0
        self.client_session = ClientSession()

    def get_next_server(self):
        server = self.backend_servers[self.server_index]
        self.server_index = (self.server_index + 1) % len(self.backend_servers)
        return server

    async def rate_limit(self, ip):
        # Allow max 100 requests per minute per IP
        MAX_REQUESTS = 100
        PERIOD = 60  # seconds

        now = int(time.time())
        key = f"rate_limit:{ip}:{now // PERIOD}"

        count = await self.redis.get(key)
        if count is None:
            await self.redis.set(key, 1, expire=PERIOD)
            return False  # Not rate limited
        elif int(count) < MAX_REQUESTS:
            await self.redis.incr(key)
            return False  # Not rate limited
        else:
            return True  # Rate limited