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

    count = args.count
    lossrate = args.lossrate
    target = AddrGenerator.resolve(args.targets[0])

    scanner = DHCPScaler(target=target,
                         count=count,
                         lossrate=lossrate,
                         **parser.scan_kwargs)
    scanner.scan()
    results = scanner.parse()

    if not parser.try_output(results):
        for i, result in enumerate(results):
            na, ta, pd = result
            print(f'{i}:\t{na}\t{ta}\t{pd}')


if __name__ == '__main__':
    main()
