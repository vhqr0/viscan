import scapy.all as sp

from typing import Optional

from ...utils.decorators import override
from ..base import BaseScanner, MixinForBaseScanner


class MixinForPcapScanner(MixinForBaseScanner):
    iface: str
    filter: str

    def get_iface(self) -> str:
        return super().get_iface()

    def get_filter(self) -> str:
        return super().get_filter()


class PcapScanner(BaseScanner, MixinForPcapScanner):
    def __init__(self, iface: Optional[str] = None, **kwargs):
        self.iface = iface if iface is not None else self.get_iface()
        self.filter = self.get_filter()
        super().__init__(**kwargs)

    @override(MixinForPcapScanner)
    def get_iface(self) -> str:
        return str(sp.conf.iface)

    @override(MixinForPcapScanner)
    def get_filter(self) -> str:
        raise NotImplementedError
