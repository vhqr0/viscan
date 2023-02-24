import logging

from ..base import OSBaseFingerPrinter
from .tcp import (
    NmapTECNScanner,
    NmapT1Scanner,
    NmapT2Scanner,
    NmapT3Scanner,
    NmapT4Scanner,
    NmapT5Scanner,
    NmapT6Scanner,
    NmapT7Scanner,
)
from .icmp import NmapU1Scanner, NmapIE1Scanner, NmapIE2Scanner


class NmapFingerPrinter(OSBaseFingerPrinter):
    # override OSBaseFingerPrinter
    logger = logging.getLogger('nmap_finger_printer')
    scanner_clses = [
        NmapTECNScanner,
        NmapT1Scanner,
        NmapT2Scanner,
        NmapT3Scanner,
        NmapT4Scanner,
        NmapT5Scanner,
        NmapT6Scanner,
        NmapT7Scanner,
        NmapU1Scanner,
        NmapIE1Scanner,
        NmapIE2Scanner,
    ]
