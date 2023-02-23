import json
import argparse

import scapy.all as sp

from typing import Any, Optional, Dict
from argparse import ArgumentParser

from ..defaults import (
    RETRY,
    TIMEWAIT,
    INTERVAL,
    POP_PORTS,
)


class GenericScanArgParser(ArgumentParser):
    scan_kwargs: Dict[str, Any]
    output_file: Optional[str]

    def __init__(self, *args, **kwargs):
        self.scan_kwargs = dict()
        self.output_file = None

        super().__init__(*args, **kwargs)

        self.add_argument('-o', '--output-file')
        self.add_argument('-i', '--iface', default=str(sp.conf.iface))
        self.add_argument('-p', '--ports', default=POP_PORTS)
        self.add_argument('-R', '--retry', type=int, default=RETRY)
        self.add_argument('-T', '--timewait', type=float, default=TIMEWAIT)
        self.add_argument('-I', '--interval', type=float, default=INTERVAL)
        self.add_argument('-O', '--open-port', type=int)
        self.add_argument('-C', '--closed-port', type=int)
        self.add_argument('-N', '--no-recursive', action='store_true')
        self.add_argument('-S', '--skip-dwim', action='store_true')
        self.add_argument('targets', nargs=argparse.REMAINDER)

    def parse_args(self, *args, **kwargs):
        args = super().parse_args(*args, **kwargs)

        sp.conf.iface = args.iface

        self.scan_kwargs.clear()
        self.scan_kwargs['retry'] = args.retry
        self.scan_kwargs['timewait'] = args.timewait
        self.scan_kwargs['interval'] = args.interval
        self.scan_kwargs['open_port'] = args.open_port
        self.scan_kwargs['closed_port'] = args.closed_port

        self.output_file = args.output_file

        return args

    def output(self, obj: Dict) -> bool:
        if self.output_file is None:
            return False
        json.dump(obj, open(self.output_file, 'w'))
        return True
