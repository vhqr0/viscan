from ..base import OSScanner
from .tcp import (
    NmapTECNFingerPrinter,
    NmapT1FingerPrinter,
    NmapT2FingerPrinter,
    NmapT3FingerPrinter,
    NmapT4FingerPrinter,
    NmapT5FingerPrinter,
    NmapT6FingerPrinter,
    NmapT7FingerPrinter,
)
from .icmp import (
    NmapU1FingerPrinter,
    NmapIE1FingerPrinter,
    NmapIE2FingerPrinter,
)


class NmapOSScanner(OSScanner):
    fp_types = [
        NmapTECNFingerPrinter,
        NmapT1FingerPrinter,
        NmapT2FingerPrinter,
        NmapT3FingerPrinter,
        NmapT4FingerPrinter,
        NmapT5FingerPrinter,
        NmapT6FingerPrinter,
        NmapT7FingerPrinter,
        NmapU1FingerPrinter,
        NmapIE1FingerPrinter,
        NmapIE2FingerPrinter,
    ]
