import sys
import argparse

from typing import Any, Dict
from argparse import ArgumentParser

from ..defaults import (
    RETRY,
    TIMEWAIT,
    INTERVAL,
    POP_PORTS,
)


class GenericScanArgParser(ArgumentParser):
    scan_kwargs: Dict[str, Any]

    def __init__(self, *args, **kwargs):
        self.scan_kwargs = dict()

        super().__init__(*args, **kwargs)

        self.add_argument('-o', '--output-file')
        self.add_argument('-i', '--iface')
        self.add_argument('-p', '--ports', default=POP_PORTS)
        self.add_argument('-R', '--retry', type=int, default=RETRY)
        self.add_argument('-T', '--timewait', type=float, default=TIMEWAIT)
        self.add_argument('-I', '--interval', type=float, default=INTERVAL)
        self.add_argument('-O', '--open-port', type=int)
        self.add_argument('-C', '--closed-port', type=int)
        self.add_argument('-N', '--no-recursive', action='store_true')
        self.add_argument('-S', '--skip-dwim', action='store_true')
        self.add_argument('targets', nargs=argparse.REMAINDER)

    def add_count_dwim(self, count: int):
        self.add_argument('-c', '--count-dwim', type=int, default=count)

    def add_step_dwim(self, step: int):
        self.add_argument('-s', '--step-dwim', type=int, default=step)

    def add_limit_dwim(self, limit: int):
        self.add_argument('-L', '--limit-dwim', type=int, default=limit)

    def add_lossrate_dwim(self, lossrate: float):
        self.add_argument('-l',
                          '--lossrate-dwim',
                          type=float,
                          default=lossrate)

    def parse_args(self, *args, **kwargs):
        args = super().parse_args(*args, **kwargs)

        if args.iface is not None:
            import scapy.all as sp
            sp.conf.iface = args.iface

        self.scan_kwargs.clear()
        self.scan_kwargs['retry'] = args.retry
        self.scan_kwargs['timewait'] = args.timewait
        self.scan_kwargs['interval'] = args.interval
        self.scan_kwargs['output_file'] = args.output_file

        if len(args.targets) == 0:
            for line in sys.stdin:
                line = line.strip()
                if len(line) == 0 or line[0] == '#':
                    continue
                args.targets.append(line)

        return args
