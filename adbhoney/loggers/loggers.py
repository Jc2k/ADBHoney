import asyncio
import datetime
import time
from contextlib import AsyncExitStack


class Loggers:

    def __init__(self):
        self.listeners = set()
        self.exit_stack = AsyncExitStack()

    async def __aenter__(self, *args):
        return self

    async def __aexit__(self, *args):
        await self.exit_stack.aclose()

    def publish(self, event):
        now = datetime.datetime.utcnow().isoformat() + 'Z'

        msg = {
            **event,
            'timestamp': now,
            'unixtime': int(time.time()),
        }
        for subscriber in list(self.listeners):
            subscriber.put_nowait(event)

    async def _worker(self, callable):
        bus = asyncio.Queue()
        self.listeners.add(bus)
        try:
            while True:
                event = await bus.get()
                try:
                    callable(event)
                except Exception:
                    self.log.exception('Error whilst recording event')
        finally:
            self.listeners.discard(bus)

    async def listen(self, logger):
        logger = await self.exit_stack.enter_async_context(logger)
        return asyncio.create_task(self._worker(logger))
