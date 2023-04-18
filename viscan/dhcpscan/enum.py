import ipaddress

import scapy.layers.dhcp6 as dhcp6

from typing import Any, Optional

from ..common.base import ResultParser
from ..common.decorators import override
from .base import DHCPBaseScanner


class DHCPEnumerator(
        ResultParser[list[tuple[str, Optional[dhcp6.DHCP6_Advertise]]]],
        DHCPBaseScanner):
    targets: list[str]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        net = ipaddress.IPv6Interface(self.linkaddr).network
        net = net.supernet(128 - self.plen + self.diff)
        self.targets = [
            str(addr.network_address) for addr in net.subnets(self.diff)
        ]

    @override(ResultParser)
    def parse(self):
        results = [(addr, None) for addr in self.targets]
        for pkt in self.recv_pkts:
            _, _, buf = pkt
            try:
                msg = self.parse_msg(buf)
                if msg is None or not isinstance(msg, dhcp6.DHCP6_Advertise):
                    continue
                trid = msg.trid
                if trid < len(results):
                    results[trid] = (results[trid][0], msg)
            except Exception as e:
                self.logger.debug('except while parsing: %s', e)
        self.result = results

    @override(ResultParser)
    def get_jsonable(self) -> dict[str, Any]:
        assert self.result is not None
        results: dict[str, Any] = dict()
        for addr, msg in self.result:
            if msg is None:
                results[addr] = None
            else:
                results[addr] = {
                    'na': self.get_na(msg),
                    'ta': self.get_ta(msg),
                    'pd': self.get_pd(msg),
                }
        return results

    @override(ResultParser)
    def show(self):
        assert self.result is not None
        for addr, msg in self.result:
            if msg is None:
                print(f'{addr}\tNone')
            else:
                na = self.get_na(msg)
                ta = self.get_ta(msg)
                pd = self.get_pd(msg)
                print(f'{addr}\t{na}\t{ta}\t{pd}')

    @override(DHCPBaseScanner)
    def get_pkts(self) -> list[tuple[str, int, bytes]]:
        pkts = []
        for trid, addr in enumerate(self.targets):
            msg = self.build_solicit(linkaddr=addr, trid=trid)
            pkts.append((self.target, 547, bytes(msg)))
        return pkts

    @override(DHCPBaseScanner)
    def send(self):
        self.send_pkts_with_timewait()


if __name__ == '__main__':
    DHCPEnumerator.main()
