import json

from .logger import Logger


class JsonLogger(Logger):

    def __init__(self, CONFIG):
        super().__init__()
        self.fp = self.enter_context(open(CONFIG['json_log'], 'w'))

    def log(self, event):
        json.dump(event, self.fp)
        self.fp.flush()