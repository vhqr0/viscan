#!/usr/bin/env bash

mypy -m viscan.host.__main__
mypy -m viscan.port.__main__
mypy -m viscan.os.nmap.__main__
mypy -m viscan.dns.__main__
