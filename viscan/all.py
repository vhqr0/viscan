# flake8: noqa

from .host import HostScanner
from .port import PortScanner
from .os import NmapScanner
from .dns import DNSScanner

from .host.__main__ import main as host_main
from .port.__main__ import main as port_main
from .os.nmap.__main__ import main as nmap_main
from .dns.__main__ import main as dns_main
