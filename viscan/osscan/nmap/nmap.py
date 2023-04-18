from ..base import OSScanner
from .tcp import NmapTCPOSScanner
from .icmp import NmapICMPOSScanner


class NmapOSScanner(OSScanner):
    fp_types = [
        NmapTCPOSScanner,
        NmapICMPOSScanner,
    ]
