import socket

from typing import Optional

from ..base import BaseScanner


class DgramScanner(BaseScanner):
    sock: socket.socket

    def __init__(self, sock: Optional[socket.socket] = None, **kwargs):
        self.sock = sock if sock is not None else self.get_sock()
        super().__init__(**kwargs)

    def get_sock(self) -> socket.socket:
        raise NotImplementedError
