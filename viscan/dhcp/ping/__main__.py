from ...utils.argparser import GenericScanArgParser
from ...utils.generators import AddrGenerator
from .scanners import DHCPPinger


def main():
    parser = GenericScanArgParser()
    args = parser.parse_args()

    target = AddrGenerator.resolve(args.targets[0])
    scanner = DHCPPinger(target=target, **parser.scan_kwargs)

    scanner.scan()
    scanner.finalize()


if __name__ == '__main__':
    main()
