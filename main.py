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
    
    def is_malicious(self, request):
        # Define malicious patterns
        patterns = [
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # SQL injection
            r"/etc/passwd",                    # Access sensitive files
            r"(\.\./\.\./)",                   # Directory traversal
            r"<script>",                       # XSS attempts
        ]
        url = request.path_qs
        for pattern in patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False
    
    async def handler(self, request):
        client_ip = request.remote

        # Rate limiting
        if await self.rate_limit(client_ip):
            return web.Response(status=429, text='Too Many Requests')

        # Malicious request blocking
        if self.is_malicious(request):
            return web.Response(status=403, text='Forbidden: Malicious Request Detected')

        # Load balancing
        backend_server = self.get_next_server()
        backend_url = f"{backend_server}{request.path_qs}"

        # Prepare headers
        headers = {key: value for key, value in request.headers.items()
                   if key.lower() != 'host'}

        # Forward the request
        try:
            async with self.client_session.request(
                method=request.method,
                url=backend_url,
                headers=headers,
                data=await request.read()
            ) as resp:
                # Build the response
                body = await resp.read()
                response_headers = dict(resp.headers)
                # Remove hop-by-hop headers
                for h in ['Transfer-Encoding', 'Connection', 'Keep-Alive', 'Proxy-Authenticate',
                          'Proxy-Authorization', 'TE', 'Trailers', 'Upgrade']:
                    response_headers.pop(h, None)
                return web.Response(
                    status=resp.status,
                    headers=response_headers,
                    body=body
                )
        except Exception as e:
            return web.Response(status=502, text=f'Bad Gateway: {e}')
    
    async def start(self, host='0.0.0.0', port=8080):
        self.redis = await create_redis_pool('redis://localhost')
        app = web.Application()
        app.add_routes([web.route('*', '/{tail:.*}', self.handler)])
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        print(f"Reverse proxy server running on {host}:{port}")
        await site.start()

        # Keep the server running
        while True:
            await asyncio.sleep(3600)

    async def close(self):
        await self.client_session.close()
        self.redis.close()
        await self.redis.wait_closed()

if __name__ == '__main__':
    backend_servers = [
        'http://localhost:8000',
        'http://localhost:8001',
        # Add more backend servers as needed
    ]

    proxy = ReverseProxy(backend_servers)

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(proxy.start())
    except KeyboardInterrupt:
        print("Shutting down proxy server...")
        loop.run_until_complete(proxy.close())
    finally:
        loop.close()