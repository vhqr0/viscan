import argparse

from argparse import ArgumentParser

from ..defaults import (
    SEND_RETRY,
    SEND_TIMEWAIT,
    SEND_INTERVAL,
    POP_PORTS,
)


class ScanArgParser(ArgumentParser):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.add_argument('-d', '--debug', action='store_true')
        self.add_argument('-o', '--output-path')
        self.add_argument('-i', '--iface')
        self.add_argument('-p', '--ports', default=POP_PORTS)
        self.add_argument('-R', '--send-retry', type=int, default=SEND_RETRY)
        self.add_argument('-T',
                          '--send-timewait',
                          type=float,
                          default=SEND_TIMEWAIT)
        self.add_argument('-I',
                          '--send-interval',
                          type=float,
                          default=SEND_INTERVAL)
        self.add_argument('-O', '--open-port', type=int)
        self.add_argument('-C', '--closed-port', type=int)
        self.add_argument('-N', '--no-dwim', action='store_true')
        self.add_argument('-S', '--skip-dwim', action='store_true')
        self.add_argument('targets', nargs=argparse.REMAINDER)

    def add_retry_dwim(self, retry: int):
        self.add_argument('-r', '--retry-dwim', type=int, default=retry)

    def add_count_dwim(self, count: int):
        self.add_argument('-c', '--count-dwim', type=int, default=count)

    def add_step_dwim(self, step: int):
        self.add_argument('-s', '--step-dwim', type=int, default=step)

    def add_limit_dwim(self, limit: int):
        self.add_argument('-l', '--limit-dwim', type=int, default=limit)

    def add_window_dwim(self, window: int):
        self.add_argument('-w', '--window-dwim', type=int, default=window)

    def add_hop_dwim(self, hop: int):
        self.add_argument('-H', '--hop-dwim', type=int, default=hop)

    def add_plen_dwim(self, plen: int):
        self.add_argument('-P', '--plen-dwim', type=int, default=plen)

    def add_diff_dwim(self, diff: int):
        self.add_argument('-D', '--diff-dwim', type=int, default=diff)

    def add_lossrate_dwim(self, lossrate: float):
        self.add_argument('-L',
                          '--lossrate-dwim',
                          type=float,
                          default=lossrate)
