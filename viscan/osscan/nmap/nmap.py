from ..base import OSScanner
from .icmp import (
    NmapU1FingerPrinter,
    NmapIE1FingerPrinter,
    NmapIE2FingerPrinter,
)


class NmapOSScanner(OSScanner):
    fp_types = [
        NmapU1FingerPrinter,
        NmapIE1FingerPrinter,
        NmapIE2FingerPrinter,
    ]
