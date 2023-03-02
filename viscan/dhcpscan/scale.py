import logging

import scapy.layers.dhcp6 as dhcp6

from typing import Any, Optional

from ..common.base import ResultParser
from ..common.decorators import override
from .base import DHCPBaseScanner
from .algos import DHCPPoolScale


class DHCPScaler(ResultParser[dict[str, Optional[DHCPPoolScale]]],
                 DHCPBaseScanner):

    logger = logging.getLogger('dhcp_scaler')

    @override(ResultParser)
    def parse(self):
        na_addrs: list[Optional[str]] = [None for _ in range(self.count)]
        ta_addrs: list[Optional[str]] = [None for _ in range(self.count)]
        pd_addrs: list[Optional[str]] = [None for _ in range(self.count)]

        for pkt in self.recv_pkts:
            _, _, buf = pkt
            try:
                msg = self.parse_msg(buf)
                if not isinstance(msg, dhcp6.DHCP6_Advertise):
                    continue
                trid = msg.trid
                if trid >= self.count:
                    continue
                na_addrs.append(self.get_na(msg))
                ta_addrs.append(self.get_ta(msg))
                pd_addrs.append(self.get_pd(msg))
            except Exception as e:
                self.logger.debug('except while parsing: %s', e)

        results: dict[str, Any] = dict()
        for name, addrs in zip(('na', 'ta', 'pd'),
                               (na_addrs, ta_addrs, pd_addrs)):
            addr_strs: list[str] = [addr for addr in addrs if addr is not None]
            if len(addr_strs) < self.lossrate * self.count:
                results[name] = None
            else:
                results[name] = DHCPPoolScale.from_strs(addr_strs)
        self.result = results

    @override(ResultParser)
    def get_jsonable(self) -> Any:
        assert self.result is not None
        results: dict[str, Any] = dict()
        for name, scale in self.result.items():
            if scale is None:
                results[name] = None
            else:
                results[name] = scale.get_jsonable()

    @override(ResultParser)
    def show(self):
        assert self.result is not None
        for name, scale in self.result.items():
            print(name)
            if scale is not None:
                scale.show()

    @override(DHCPBaseScanner)
    def get_pkts(self) -> list[tuple[str, int, bytes]]:
        pkts = []
        for trid in range(self.count):
            buf = self.build_solicit(trid=trid)
            pkts.append((self.target, 547, buf))
        return pkts

    @override(DHCPBaseScanner)
    def send(self):
        self.send_pkts_with_timewait()


if __name__ == '__main__':
    DHCPScaler.main()
