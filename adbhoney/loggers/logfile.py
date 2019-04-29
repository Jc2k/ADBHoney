import json
import sys

from .logger import Logger


class Logfile(Logger):

    def __init__(self, CONFIG):
        super().__init__()
        self.fp = sys.stdout

        if CONFIG['logfile'] is not None:
            self.fp = self.enter_context(open(CONFIG['logfile'], 'w'))

    def log(self, event):
        message = event['message'].format(**event)
        print(message, file=self.fp)
        self.fp.flush()
