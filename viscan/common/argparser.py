import logging
import argparse

from argparse import ArgumentParser, Namespace

from ..defaults import (
    LOG_FORMAT,
    LOG_DATEFMT,
    RETRY,
    TIMEWAIT,
    INTERVAL,
    POP_PORTS,
)


class ScanArgParser(ArgumentParser):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.add_argument('-o', '--output-path')
        self.add_argument('-i', '--iface')
        self.add_argument('-p', '--ports', default=POP_PORTS)
        self.add_argument('-R', '--retry', type=int, default=RETRY)
        self.add_argument('-T', '--timewait', type=float, default=TIMEWAIT)
        self.add_argument('-I', '--interval', type=float, default=INTERVAL)
        self.add_argument('-O', '--open-port', type=int)
        self.add_argument('-C', '--closed-port', type=int)
        self.add_argument('-N', '--no-dwim', action='store_true')
        self.add_argument('-S', '--skip-dwim', action='store_true')
        self.add_argument('targets', nargs=argparse.REMAINDER)

    def add_count_dwim(self, count: int):
        self.add_argument('-c', '--count-dwim', type=int, default=count)

    def add_step_dwim(self, step: int):
        self.add_argument('-s', '--step-dwim', type=int, default=step)

    def add_limit_dwim(self, limit: int):
        self.add_argument('-l', '--limit-dwim', type=int, default=limit)

    def add_lossrate_dwim(self, lossrate: float):
        self.add_argument('-L',
                          '--lossrate-dwim',
                          type=float,
                          default=lossrate)

    def parse_args(self, *args, **kwargs) -> Namespace:
        args = super().parse_args(*args, **kwargs)
        debug = args.debug
        level = 'DEBUG' if debug else 'INFO'
        logging.basicConfig(level=level,
                            format=LOG_FORMAT,
                            datefmt=LOG_DATEFMT)
        return args
