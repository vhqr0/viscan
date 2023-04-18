import socket
import ipaddress
import functools

from typing import Any, Optional

from ..common.base import ResultParser
from ..common.decorators import override
from .base import DHCPBaseScanner, DHCPSoliciter
from .scale import DHCPScaler, DHCPPoolScale


class DHCPLocator(ResultParser[int], DHCPBaseScanner):
    scaler: DHCPScaler
    soliciter: DHCPSoliciter
    na_scale: Optional[DHCPPoolScale]
    ta_scale: Optional[DHCPPoolScale]
    pd_scale: Optional[DHCPPoolScale]

    def __init__(self, sock: Optional[socket.socket] = None, **kwargs):
        sock = sock if sock is not None else self.get_sock()
        super().__init__(sock=sock, **kwargs)
        self.scaler = DHCPScaler(sock=sock, **kwargs)
        self.soliciter = DHCPSoliciter(sock=sock, **kwargs)

    def _accept(self, addr: str) -> bool:
        try:
            msg = self.soliciter.retrieve(addr)
            if msg is None:
                return False
            na = self.get_na(msg)
            if na is not None and self.na_scale is not None:
                return na in self.na_scale
            ta = self.get_ta(msg)
            if ta is not None and self.ta_scale is not None:
                return ta in self.ta_scale
            pd = self.get_pd(msg)
            if pd is not None and self.pd_scale is not None:
                return pd in self.pd_scale
        except Exception as e:
            self.logger.debug('except while scanning: %s', e)
        return False

    @functools.cache
    def accept(self, addr: str) -> bool:
        for _ in range(self.retry):
            if self._accept(addr):
                return True
        return False

    @override(DHCPBaseScanner)
    def scan_and_parse(self):
        try:
            self.scaler.scan_and_parse()
            assert self.scaler.result is not None
            self.na_scale = self.scaler.result['na']
            self.ta_scale = self.scaler.result['ta']
            self.pd_scale = self.scaler.result['pd']

            subnet = ipaddress.IPv6Interface(self.linkaddr).network

            while subnet.prefixlen > self.step:
                next_subnet = subnet.supernet(self.step)
                first = next_subnet.network_address
                last = next_subnet.broadcast_address
                if not self.accept(str(first)) or not self.accept(str(last)):
                    break
                subnet = next_subnet
                self.logger.debug('accept %s', subnet)

            self.result = subnet.prefixlen
        except Exception as e:
            self.logger.error('error while scanning: %s', e)
            raise

    @override(ResultParser)
    def get_jsonable(self) -> dict[str, Any]:
        assert self.result is not None and self.scaler.result is not None
        return {'prefixlen': self.result, 'scale': self.scaler.get_jsonable()}

    @override(ResultParser)
    def show(self):
        assert self.result is not None and self.scaler.result is not None
        self.scaler.show()
        print(f'prefixlen\t{self.result}')


if __name__ == '__main__':
    DHCPLocator.main()
