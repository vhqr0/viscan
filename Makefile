lint: flake8 mypy

mypy:
	mypy --ignore-missing-imports --check-untyped-defs -m viscan.all

flake8:
	flake8 viscan

yapf:
	yapf -i -r viscan

build:
	python3 -m build

viz:
	pyreverse -o png viscan
