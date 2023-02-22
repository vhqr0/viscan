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

    retry: int
    timewait: float
    interval: float

    logger = logging.getLogger('scanner')

    def __init__(self, retry=RETRY, timewait=TIMEWAIT, interval=INTERVAL):
        self.done = False

        self.retry = retry
        self.timewait = timewait
        self.interval = interval

    def scan(self):
        self.done = False

        receiver = threading.Thread(target=self.receive_loop)
        receiver.start()

        exc: Optional[Exception] = None

        try:
            self.send_loop()
        except Exception as e:
            exc = e
            self.logger.error('except while scanning: %s', e)
        finally:
            self.done = True
            receiver.join()

        if exc is not None:
            raise exc

    def send_loop(self):
        raise NotImplementedError

    def receive_loop(self):
        raise NotImplementedError
