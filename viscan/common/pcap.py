import select

from pcap import pcap
from scapy.config import conf as spconf
from scapy.sendrecv import send as spsend
import scapy.layers.inet6 as inet6

from typing import Any, Optional
from argparse import Namespace

from .base import SRScanner, MainRunner
from .decorators import override


class PcapScanner(SRScanner[inet6.IPv6, bytes], MainRunner):
    iface: str

    def __init__(self, iface: Optional[str] = None, **kwargs):
        super().__init__()
        self.iface = iface if iface is not None else str(spconf.iface)

    def get_filter(self) -> str:
        raise NotImplementedError

    def get_sniffer(self) -> pcap:
        sniffer = pcap(name=self.iface, promisc=False, timeout_ms=1)
        sniffer.setfilter(self.get_filter())
        sniffer.setnonblock()
        return sniffer

    @override(SRScanner)
    def recv(self):
        sniffer = self.get_sniffer()
        while not self.scan_done:
            rlist, _, _ = select.select([sniffer.fd], [], [], 1)
            if rlist:
                sniffer.dispatch(1, self.on_pcap_recv)

    def on_pcap_recv(self, ts: float, buf: bytes):
        self.append_recv_pkt(buf)

    @override(SRScanner)
    def send_pkt(self, pkt: inet6.IPv6):
        dst = pkt.dst
        if spconf.route6.route(dst)[0] != self.iface:
            self.logger.warning('dst to other iface: %s', dst)
        else:
            spsend(pkt, iface=self.iface, verbose=0)

    @classmethod
    @override(MainRunner)
    def parse_args(cls, args: Namespace) -> dict[str, Any]:
        iface = args.iface
        if iface is not None:
            spconf.iface = iface
        return super().parse_args(args)
