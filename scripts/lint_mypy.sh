#!/usr/bin/env bash

mypy --ignore-missing-imports --check-untyped-defs -m viscan.all
