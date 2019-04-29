import json
from contextlib import AsyncExitStack

from cachetools import LRUCache
from hpfeeds.asyncio import ClientSession


class HpfeedsLogger:

    """
    Log full complete sessions to hpfeeds.
    """

    def __init__(self, host, port, ident, secret, ssl=None):
        super().__init__(*args, **kwargs)
        self.sessions = LRUCache(1000)
        self.session = ClientSession(host, port, ident, secret, ssl)
        self.exit_stack = AsyncExitStack()

    async def __aenter__(self):
        await self.exit_stack.enter_async_context(self.session)
        return super().__aenter__()

    def log(self, event):
        session_id = event['session_id']

        if event['type'] == 'adbhoney.session.connect':
            self.sessions[session_id] = {
                'src_ip': event['src_ip'],
                'src_port': event['src_port'],
                'dst_ip': event['dst_ip'],
                'dst_port': event['dst_port'],
                'sensor': event['sensor'],
                'shasum': [],
            }
            return

        session = self.sessions.get(session_id, {})

        if event['type'] == 'adbhoney.session.file_upload':
            session['shasum'].append(event['shasum'])

        elif event['type'] == 'adbhoney.session.closed':
            session.update({
                'closedmessage': event['closedmessage'],
                'duration': event['duration'],
            })

            try:
                self.publish(
                    'adbhoney',
                    json.dumps(event)
                )
            finally:
               self.sessions.pop(session_id, None)