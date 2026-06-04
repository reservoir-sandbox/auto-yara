.PHONY: format lint

format:
	black .
	isort .

lint:
	black --check .
	isort --check-only .
	flake8 .
	mypy .
