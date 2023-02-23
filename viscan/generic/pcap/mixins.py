import select

import pcap
import scapy.all as sp

from typing import Any, Mapping

from ...utils.decorators import override
from ..base import GenericScanMixin
from .scanners import MixinForPcapScanner


class PcapScanMixin(GenericScanMixin[sp.IPv6, bytes],
                    MixinForPcapScanner):
    def get_sniffer(self) -> pcap.pcap:
        sniffer = pcap.pcap(name=self.iface, promisc=False, timeout_ms=1)
        sniffer.setfilter(self.filter)
        sniffer.setnonblock()
        return sniffer

    @override(GenericScanMixin)
    def send_pkt(self, pkt: sp.IPv6):
        dst = pkt.dst
        if sp.conf.route6.route(dst)[0] != self.iface:
            self.logger.warning('dst to other iface: %s', dst)
            return
        sp.send(pkt, iface=self.iface, verbose=0)

    @override(GenericScanMixin)
    def receive_loop(self):
        sniffer = self.get_sniffer()
        while not self.done:
            rlist, _, _ = select.select([sniffer.fd], [], [], 1)
            if rlist:
                sniffer.dispatch(1, self.on_receive)

    def on_receive(self, ts: float, buf: bytes):
        self.add_result(buf)


class FilterMixin(MixinForPcapScanner):
    filter_template: str = 'ip6'

    @override(MixinForPcapScanner)
    def get_filter(self):
        return self.filter_template.format_map(self.get_filter_context())

    def get_filter_context(self) -> Mapping[str, Any]:
        return dict()
