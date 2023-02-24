import pprint

from ...defaults import (
    DHCP_SCALE_COUNT,
    DHCP_SCALE_LOSSRATE,
)
from ...utils.argparser import GenericScanArgParser
from ...utils.generators import AddrGenerator
from .scanners import DHCPScaler


def main():
    parser = GenericScanArgParser()
    parser.add_count_dwim(DHCP_SCALE_COUNT)
    parser.add_lossrate_dwim(DHCP_SCALE_LOSSRATE)
    args = parser.parse_args()

    count = args.count_dwim
    lossrate = args.lossrate_dwim
    target = AddrGenerator.resolve(args.targets[0])

    scanner = DHCPScaler(target=target,
                         count=count,
                         lossrate=lossrate,
                         **parser.scan_kwargs)
    scanner.scan()
    results = scanner.parse()

    if not parser.try_output(results):
        for k, v in results.items():
            print(f'--- {k} ---')
            pprint.pprint(v)


if __name__ == '__main__':
    main()
