import threading
import logging

from typing import Optional

from ...defaults import (
    RETRY,
    TIMEWAIT,
    INTERVAL,
)


class BaseScanner:
    done: bool
    exc: Optional[Exception]

    retry: int
    timewait: float
    interval: float

    logger = logging.getLogger('scanner')

    def __init__(self, retry=RETRY, timewait=TIMEWAIT, interval=INTERVAL):
        self.done = False
        self.exc = None

        self.retry = retry
        self.timewait = timewait
        self.interval = interval

    def scan(self):
        self.done = False
        self.exc = None

        receiver = threading.Thread(target=self.receiver)
        receiver.start()

        try:
            self.sender()
        except Exception as e:
            self.exc = e
            self.logger.error('except while scanning: %s', e)
        finally:
            self.done = True
            receiver.join()

        if self.exc is not None:
            raise self.exc

    def sender(self):
        raise NotImplementedError

    def receiver(self):
        raise NotImplementedError
