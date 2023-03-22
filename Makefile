lint: mypy flake8

mypy:
	mypy --ignore-missing-imports --check-untyped-defs -m viscan.all

flake8:
	flake8 viscan/**/*.py

build:
	python3 -m build

yapf:
	yapf viscan/**/*.py

viz:
	pyreverse -o png viscan
