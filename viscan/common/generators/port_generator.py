import re

from ...defaults import MAX_TARGETS


class PortGenerator:
    ports: set[int]
    skip_check_max_targets: bool

    single_port_re = re.compile(r'^(\d+)$')
    range_ports_re = re.compile(r'^(\d+)-(\d+)$')

    def __init__(self, ports: list[str], skip_check_max_targets: bool = False):
        self.ports = set()
        self.skip_check_max_targets = skip_check_max_targets
        for port in ports:
            if self.try_add_single_port(port) or \
               self.try_add_range_ports(port):
                continue
            raise ValueError(f'invalid port str: {port}')

    def add_port(self, port: int):
        self.ports.add(port)
        if not self.skip_check_max_targets and len(self.ports) > MAX_TARGETS:
            raise ValueError('too many ports')

    def try_add_single_port(self, port_str: str) -> bool:
        res = self.single_port_re.match(port_str)
        if res is None:
            return False
        port = int(res[1])
        if not 0 < port <= 65535:
            raise ValueError(f'invalid single port: {port}')
        self.add_port(port)
        return True

    def try_add_range_ports(self, port_str: str) -> bool:
        res = self.range_ports_re.match(port_str)
        if res is None:
            return False
        port1, port2 = int(res[1]), int(res[2])
        if not 0 < port1 < port2 <= 65536:
            raise ValueError(f'invalid range ports: {port1}-{port2}')
        for port in range(port1, port2):
            self.add_port(port)
        return True
