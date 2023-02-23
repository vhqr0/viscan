import socket

from typing import Optional

from ...utils.decorators import override
from ..base import BaseScanner, MixinForBaseScanner


class MixinForDgramScanner(MixinForBaseScanner):
    sock: socket.socket

    def get_sock(self) -> socket.socket:
        return super().get_sock()


class DgramScanner(BaseScanner, MixinForDgramScanner):
    def __init__(self, sock: Optional[socket.socket] = None, **kwargs):
        self.sock = sock if sock is not None else self.get_sock()
        super().__init__(**kwargs)

    @override(MixinForDgramScanner)
    def get_sock(self) -> socket.socket:
        raise NotImplementedError
