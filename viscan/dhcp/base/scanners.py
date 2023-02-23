import random

import scapy.layers.dhcp6 as dhcp6

from ...generic.dgram import DgramScanner, MixinForDgramScanner


class MixinForDHCPBaseScanner(MixinForDgramScanner):
    target: str
    duid: dhcp6.DUID_LL


class DHCPBaseScanner(DgramScanner, MixinForDHCPBaseScanner):

    def __init__(self, target: str, **kwargs):
        self.target = target
        self.duid = dhcp6.DUID_LL(lladdr=random.randbytes(6))
        super().__init__(**kwargs)
