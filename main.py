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
