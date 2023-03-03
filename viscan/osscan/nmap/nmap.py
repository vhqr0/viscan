from ...common.decorators import auto_add_logger
from ..base import OSScanner
from .tcp import NmapTCPOSScanner
from .icmp import NmapICMPOSScanner


@auto_add_logger
class NmapOSScanner(OSScanner):
    fp_types = [
        NmapTCPOSScanner,
        NmapICMPOSScanner,
    ]
