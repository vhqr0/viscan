import scapy.all as sp

from typing import Optional

from ..base import BaseScanner


class PcapScanner(BaseScanner):
    iface: str
    filter: str

    def __init__(self, iface: Optional[str] = None, **kwargs):
        self.iface = iface if iface is not None else self.get_iface()
        self.filter = self.get_filter()
        super().__init__(**kwargs)

    def get_iface(self) -> str:
        return str(sp.conf.iface)

    def get_filter(self) -> str:
        raise NotImplementedError
