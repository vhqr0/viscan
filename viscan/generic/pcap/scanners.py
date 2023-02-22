import select
import logging

import pcap
import scapy.all as sp

from typing import Optional

from ..base import (
    BaseScanner,
    GenericScanMixin,
    StatelessScanMixin,
    StatefulScanMixin,
)


class PcapScanner(GenericScanMixin[sp.IPv6, bytes], BaseScanner):
    iface: str

    logger = logging.getLogger('pcap_scanner')

    filter: Optional[str] = None

    def __init__(self, iface: Optional[str] = None, **kwargs):
        self.iface = iface if iface is not None else str(sp.conf.iface)
        super().__init__(**kwargs)

    def get_filter(self) -> str:
        if self.filter is not None:
            return self.filter
        raise NotImplementedError

    def send_pkt(self, pkt: sp.IPv6):
        dst = pkt.dst
        if sp.conf.route6.route(dst)[0] != self.iface:
            self.logger.warning('dst to other iface: %s', dst)
            return
        sp.send(pkt, iface=self.iface, verbose=0)

    def get_sniffer(self) -> pcap.pcap:
        sniffer = pcap.pcap(name=self.iface, promisc=False, timeout_ms=1)
        sniffer.setfilter(self.get_filter())
        sniffer.setnonblock()
        return sniffer

    def receive_loop(self):
        sniffer = self.get_sniffer()
        while not self.done:
            rlist, _, _ = select.select([sniffer.fd], [], [], 1)
            if rlist:
                sniffer.dispatch(1, self.on_receive)

    def on_receive(self, ts: float, buf: bytes):
        self.add_result(buf)


class PcapStatelessScanner(StatelessScanMixin, PcapScanner):
    pass


class PcapStatefulScanner(StatefulScanMixin, PcapScanner):
    pass
