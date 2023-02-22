import logging

from ...defaults import (
    RETRY,
    TIMEWAIT,
    INTERVAL,
)


class BaseScanner:
    retry: int
    timewait: float
    interval: float

    logger = logging.getLogger('scanner')

    def __init__(self,
                 retry=RETRY,
                 timewait=TIMEWAIT,
                 interval=INTERVAL,
                 **kwargs):
        self.retry = retry
        self.timewait = timewait
        self.interval = interval

        for k, v in kwargs.items():
            self.logger.warning('unused initial args: %s %s', k, v)

    def scan(self):
        raise NotImplementedError
