import scapy.layers.inet as inet
import scapy.layers.inet6 as inet6
import scapy.layers.dns as dns

from ..common.base import MainRunner
from ..common.pcap import PcapScanner
from ..common.decorators import override, auto_add_logger
from .base import RouteSubTracer, RouteTracer


@auto_add_logger
class DNSRouteSubTracer(RouteSubTracer, PcapScanner):
    target: str
    target_port: int
    target_name: str

    filter_template = 'ip6 and ' \
        '(' \
        ' icmp6[icmp6type]==icmp6-timeexceeded or ' \
        ' (udp dst port {} and udp src port {} and ip6 src {})' \
        ')'

    @override(RouteSubTracer)
    def parse(self):
        for pkt in self.recv_pkts:
            try:
                if inet.UDP in pkt:
                    self.result = (pkt.src, True)
                    return
                # TODO: deeper analysis
                self.result = (pkt.src, False)
                return
            except Exception as e:
                self.logger.debug('except whilejhla parsing: %s', e)
        raise RuntimeError('no response')

    @override(PcapScanner)
    def get_filter(self) -> str:
        return self.filter_template.format(self.port, self.target_port,
                                           self.target)

    @override(PcapScanner)
    def get_pkt(self) -> inet6.IPv6:
        pkt = inet6.IPv6(dst=self.target, hlim=self.hop) / \
            inet.UDP(sport=self.port, dport=self.target_port) / \
            dns.DNS(qd=dns.DNSQR(qname=self.target_name, qtype='AAAA'))
        return pkt


@auto_add_logger
class DNSRouteTracer(RouteTracer, DNSRouteSubTracer, MainRunner):
    sub_tracer_type = DNSRouteSubTracer


if __name__ == '__main__':
    DNSRouteTracer.main()
