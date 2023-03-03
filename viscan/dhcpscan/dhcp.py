import socket
import base64

import scapy.layers.dhcp6 as dhcp6

from typing import Any, Optional

from ..common.base import ResultParser
from ..common.decorators import override, auto_add_logger
from .base import DHCPBaseScanner
from .ping import DHCPPinger
from .scale import DHCPScaler, DHCPPoolScale
from .locate import DHCPLocator
from .enum import DHCPEnumerator


class DHCPInfo:
    target: str
    linkaddr: str
    plen: int
    reply: dhcp6.DHCP6_Reply
    advertise: dhcp6.DHCP6_Advertise
    subnets: dict[str, Optional[dict[str, Optional[DHCPPoolScale]]]]

    def __init__(self, target: str, linkaddr: str, plen: int,
                 reply: dhcp6.DHCP6_Reply, advertise: dhcp6.DHCP6_Advertise,
                 subnets: dict[str, Optional[dict[str,
                                                  Optional[DHCPPoolScale]]]]):
        self.target = target
        self.linkaddr = linkaddr
        self.plen = plen
        self.reply = reply
        self.advertise = advertise
        self.subnets = subnets

    def get_jsonable(self) -> dict[str, Any]:
        subnets_jsonable: dict[str, Optional[dict[str, Any]]] = dict()
        for addr, scales in self.subnets.items():
            if scales is None:
                subnets_jsonable[addr] = None
            else:
                scales_jsonable: dict[str, Any] = dict()
                for name, scale in scales.items():
                    if scale is None:
                        scales_jsonable[name] = None
                    else:
                        scales_jsonable[name] = scale.get_jsonable()
                subnets_jsonable[addr] = scales_jsonable
        return {
            'target': self.target,
            'linkaddr': self.linkaddr,
            'plen': self.plen,
            'reply': base64.b64encode(bytes(self.reply)).decode(),
            'advertise': base64.b64encode(bytes(self.advertise)).decode(),
            'subnets': subnets_jsonable,
        }

    def show(self):
        print(f'target\t{self.target}')
        print(f'linkaddr\t{self.linkaddr}')
        print(f'plen\t{self.plen}')
        print(f'reply\t{self.reply.summary()}')
        print(f'advertise\t{self.advertise.summary()}')
        print('subnets')
        for addr, scales in self.subnets.items():
            print(f'{addr}')
            if scales is not None:
                for name, scale in scales.items():
                    if scale is not None:
                        print(f'{name}\t{scale.summary()}')


@auto_add_logger
class DHCPScanner(ResultParser[DHCPInfo], DHCPBaseScanner):
    kwargs: dict[str, Any]

    def __init__(self, sock: Optional[socket.socket] = None, **kwargs):
        sock = sock if sock is not None else self.get_sock()
        kwargs['sock'] = sock
        super().__init__(**kwargs)
        self.kwargs = kwargs

    def ping(self) -> tuple[dhcp6.DHCP6_Reply, dhcp6.DHCP6_Advertise]:
        pinger = DHCPPinger(**self.kwargs)
        pinger.scan_and_parse()
        assert pinger.result is not None
        reply = pinger.result['reply']
        advertise = pinger.result['advertise']
        if not isinstance(reply, dhcp6.DHCP6_Reply):
            raise RuntimeError('no reply')
        if not isinstance(advertise, dhcp6.DHCP6_Advertise):
            raise RuntimeError('no advertise')
        if self.get_na(advertise) is None and \
           self.get_ta(advertise) is None and \
           self.get_pd(advertise) is None:
            raise RuntimeError('no addrs')
        return reply, advertise

    def locate(self) -> int:
        locator = DHCPLocator(**self.kwargs)
        locator.scan_and_parse()
        assert locator.result is not None
        return locator.result

    def enumerate(self, plen: int) -> list[str]:
        kwargs = self.kwargs.copy()
        kwargs['plen'] = plen
        enumerator = DHCPEnumerator(**kwargs)
        enumerator.scan_and_parse()
        assert enumerator.result is not None
        addrs = []
        for addr, msg in enumerator.result:
            if msg is None:
                continue
            if self.get_na(msg) is None and \
               self.get_ta(msg) is None and \
               self.get_pd(msg) is None:
                continue
            addrs.append(addr)
        return addrs

    def scale(self, addr: str) -> dict[str, Optional[DHCPPoolScale]]:
        kwargs = self.kwargs.copy()
        kwargs['linkaddr'] = addr
        scaler = DHCPScaler(**kwargs)
        scaler.scan_and_parse()
        assert scaler.result is not None
        return scaler.result

    @override(ResultParser)
    def get_jsonable(self) -> dict[str, Any]:
        assert self.result is not None
        return self.result.get_jsonable()

    @override(ResultParser)
    def show(self):
        assert self.result is not None
        self.result.show()

    @override(DHCPBaseScanner)
    def scan_and_parse(self):
        try:
            reply, advertise = self.ping()

            plen = self.locate()

            addrs = self.enumerate(plen)

            subnets: dict[str, Optional[dict[str, Optional[DHCPPoolScale]]]]
            if len(addrs) > self.limit:
                subnets = {addr: None for addr in addrs}
            else:
                subnets = {addr: self.scale(addr) for addr in addrs}

            self.result = DHCPInfo(target=self.target,
                                   linkaddr=self.linkaddr,
                                   plen=plen,
                                   reply=reply,
                                   advertise=advertise,
                                   subnets=subnets)
        except Exception as e:
            self.logger.error('error while scanning: %s', e)
            raise
