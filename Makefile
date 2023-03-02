lint:
	mypy --ignore-missing-imports --check-untyped-defs -m viscan.all

viz:
	pyreverse -o png viscan
