import logging

from typing import Optional

from ...defaults import (
    RETRY,
    TIMEWAIT,
    INTERVAL,
)
from ...utils.decorators import override


class MixinForBaseScanner:
    retry: int
    timewait: float
    interval: float
    output_file: Optional[str]
    logger: logging.Logger

    def run(self):
        super().run()

    def scan(self):
        super().scan()

    def finalize(self):
        super().finalize()


class BaseScanner(MixinForBaseScanner):
    logger = logging.getLogger('scanner')

    def __init__(self,
                 retry: int = RETRY,
                 timewait: float = TIMEWAIT,
                 interval: float = INTERVAL,
                 output_file: Optional[str] = None,
                 **kwargs):
        self.retry = retry
        self.timewait = timewait
        self.interval = interval
        self.output_file = output_file

        for k, v in kwargs.items():
            self.logger.warning('unused initial args: %s %s', k, v)

    @classmethod
    @override(MixinForBaseScanner)
    def main(cls, *args, **kwargs):
        raise NotImplementedError

    @override(MixinForBaseScanner)
    def scan(self):
        raise NotImplementedError

    @override(MixinForBaseScanner)
    def finalize(self):
        raise NotImplementedError
