import random

import scapy.layers.dhcp6 as dhcp6

from ...defaults import (
    DHCP_LOCATE_STEP,
    DHCP_SCALE_COUNT,
    DHCP_SCALE_LOSSRATE,
)
from ...generic.dgram import DgramScanner, MixinForDgramScanner


class MixinForDHCPBaseScanner(MixinForDgramScanner):
    target: str
    step: int
    count: int
    lossrate: float
    duid: dhcp6.DUID_LL


class DHCPBaseScanner(DgramScanner, MixinForDHCPBaseScanner):

    def __init__(self,
                 target: str,
                 step: int = DHCP_LOCATE_STEP,
                 count: int = DHCP_SCALE_COUNT,
                 lossrate: float = DHCP_SCALE_LOSSRATE,
                 **kwargs):
        self.target = target
        self.step = step
        self.count = count
        self.lossrate = lossrate
        self.duid = dhcp6.DUID_LL(lladdr=random.randbytes(6))
        super().__init__(**kwargs)
