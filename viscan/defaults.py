LOG_FORMAT = '%(asctime)s %(name)s %(levelname)s %(message)s'
LOG_DATEFMT = '%y-%m-%d %H:%M:%S'

RETRY = 2
TIMEWAIT = 1.0
INTERVAL = 0.1

MAX_TARGETS = 65536

TRACEROUTE_LIMIT = 16

DNS_LIMIT = 4

DHCP_SCALE_COUNT = 64
DHCP_SCALE_LOSSRATE = 0.5

DHCP_LOCATE_STEP = 4

# from nmap/portlist.cc::random_port_cheat::pop_ports
POP_PORTS = '80,23,443,21,22,25,3389,110,445,139,' \
    '143,53,135,3306,8080,1723,111,995,993,5900,1025,587,8888,199,1720'
