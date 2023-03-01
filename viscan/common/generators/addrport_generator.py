from ...defaults import MAX_TARGETS
from .addr_generator import AddrGenerator
from .port_generator import PortGenerator


class AddrPortGenerator(AddrGenerator, PortGenerator):
    addrports: list[tuple[str, int]]

    def __init__(self,
                 addrs: list[str],
                 ports: list[str],
                 skip_check_max_targets: bool = False):
        AddrGenerator.__init__(self,
                               addrs,
                               skip_check_max_targets=skip_check_max_targets)
        PortGenerator.__init__(self,
                               ports,
                               skip_check_max_targets=skip_check_max_targets)
        if not skip_check_max_targets and \
           len(self.addrs) * len(self.ports) > MAX_TARGETS:
            raise ValueError('too many targets')
        self.addrports = [(addr, port) for addr in self.addrs
                          for port in self.ports]
