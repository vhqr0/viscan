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
        for scale in ('na_scale', 'ta_scale', 'pd_scale'):
            print(f'--- {scale} ---')
            pprint.pprint(results[scale])
        for i, result in enumerate(results['results']):
            na, ta, pd = result
            print(f'{i}:\t{na}\t{ta}\t{pd}')


if __name__ == '__main__':
    main()
