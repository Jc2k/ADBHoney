from contextlib import AsyncExitStack


class Logger:

    def __init__(self):
        self.exit_stack = AsyncExitStack()

    async def __aenter__(self):
        return self.log
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.exit_stack.aclose()

    def log(self, event):
        raise NotImplementedError(self.log)