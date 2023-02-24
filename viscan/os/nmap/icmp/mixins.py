from typing import Any, Mapping

from ....generic.pcap import FilterMixin
from ....utils.decorators import override
from ...base import OSScanMixin


class NmapICMPScanMixin(FilterMixin, OSScanMixin):
    # override FilterMixin
    filter_template = 'ip6 src {target} and ' \
        'icmp6[icmp6type]==icmp6-echoreply and ' \
        'icmp6[4:2]=={port}'

    @override(FilterMixin)
    def get_filter_context(self) -> Mapping[str, Any]:
        return {'target': self.target, 'port': self.port}
