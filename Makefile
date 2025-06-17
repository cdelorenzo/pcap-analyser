# Makefile for Python CLI Tool using Poetry

.PHONY: bootstrap install run test lint format docker-build clean help

# Project variables
APP_NAME=src/pcap_analyser
ENTRY_POINT=src/pcap_analyser/cli.py

help:
	@echo "Available targets:"
	@echo "  bootstrap     Set up Poetry if needed (bin/bootstrap-poetry.sh)"
	@echo "  install       Install dependencies and check environment"
	@echo "  run           Run the CLI tool (use ARGS=...)"
	@echo "  test          Run all tests with pytest"
	@echo "  lint          Lint code with flake8"
	@echo "  format        Format code with black"
	@echo "  docker-build  Build the Docker image"
	@echo "  clean         Remove build, dist, cache, and __pycache__ files"

bootstrap:
	bin/bootstrap-poetry.sh

install:
	@echo "Installing dependencies..."
	poetry config virtualenvs.in-project true
	poetry install
	poetry check
	poetry run pip3 check

run:
	@echo "Running CLI tool..."
	poetry run python $(ENTRY_POINT) $(ARGS)

test:
	@echo "Running tests..."
	poetry run pytest tests/ --cov=src --cov-report=xml

lint:
	@echo "Linting with flake8..."
	poetry run flake8 $(APP_NAME) tests

format:
	@echo "Formatting with black..."
	poetry run black $(APP_NAME) tests

docker-build:
	@echo "Building Docker image..."
	docker build -t $(APP_NAME):latest .

clean:
	@echo "Cleaning up __pycache__ and build artifacts..."
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .coverage
	rm -rf .coverage.xml
	rm -rf htmlcov/
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
