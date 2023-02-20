import logging

import scapy.all as sp

from typing import Optional

from ..generic import PcapStatefulScanner


class OSScanner(PcapStatefulScanner):
    target: str
    open_port: Optional[int]
    closed_port: Optional[int]

    logger = logging.getLogger('os_scanner')

    def __init__(self,
                 target: str,
                 open_port: Optional[int] = None,
                 closed_port: Optional[int] = None,
                 **kwargs):
        self.target = target
        self.open_port = open_port
        self.closed_port = closed_port
        super().__init__(**kwargs)

    def parse(self) -> Optional[bytes]:
        if not self.results:
            return None
        return sp.raw(sp.Ether(self.results[0])[sp.IPv6])
