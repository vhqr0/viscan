from ...utils.argparser import GenericScanArgParser
from ...utils.generators import AddrGenerator
from .scanners import DHCPPinger


def main():
    parser = GenericScanArgParser()
    args = parser.parse_args()

    target = AddrGenerator.resolve(args.targets[0])
    scanner = DHCPPinger(target=target, **parser.scan_kwargs)

    scanner.scan()
    results = scanner.parse()

    if not parser.try_output(results):
        for k, v in results.items():
            print(f'{k}:\t{v}')


if __name__ == '__main__':
    main()
