# PCAP Analyser

A Python tool for analysing and providing a tool to pass or fail a network packet capture (PCAP) given a baseline set of thresholds. This tool also provides the ability to create a baseline threshold configuration 

comprehensive analysis of network traffic, including protocol distribution, IP statistics, port usage, and payload analysis.

## Requirements

- Python 3.11 or higher
- Poetry + dependencies
- Run `make bootstrap`


## Local environment setup

1. Clone the repository:
```bash
git clone https://pcap-analyzer.git
cd pcap-analyzer
```

2. Install Poetry and make sure you have required setup run:

```bash
make bootstrap
```

Or, directly:

```bash
bin/bootstrap-poetry.sh
```

This will install Poetry (if needed) and check your setup.

Add Poetry to your PATH (if needed):

```bash
export PATH="$HOME/.local/bin:$PATH"
```

3. Install Project Dependencies

```bash
make install
```

## Poetry Virtual Environment Setup

Poetry automatically manages a virtual environment for your project.  
To ensure the venv is created inside your project directory (recommended for Makefile integration), run:

This will create a `.venv/` directory in your project root.

To activate the venv manually (for running commands directly):

```bash
source .venv/bin/activate
```

Or, use `poetry run <command>` to run any command inside the venv without activating it:

```bash
poetry run python src/pcap_analyser/cli.py
```

You can also use the Makefile targets, which are already set up to use Poetry’s venv:

```bash
make install
make run ARGS="analyze yourfile.pcapng -o output.json"
make test
make lint
```


## Usage

```bash
make run ARGS="analyze 2_0_22_sunny_day_profile_20240925_run_1.pcapng -o output.json -v"
make run ARGS="init"
make run ARGS="baseline 2_0_22_sunny_day_profile_20240925_run_1.pcapng -o baseline.json"
```

## Development

1. Install development dependencies:
```bash
make install
```

2. Run tests:
```bash
make test
```

3. Run linting:
```bash
make lint
```

4. Format code:
```bash
make format
```

## Project Structure

```
pcap-analyzer/
├── src/
│   ├── pcap_analyzer/
│   │   ├── core/
│   │   │   └── analyzer.py
│   │   ├── utils/
│   │   │   └── logger.py
│   │   └── config/
│   │       └── settings.py
│   └── main.py
├── tests/
│   ├── unit/
│   └── integration/
├── results/
├── requirements.txt
├── requirements-dev.txt
├── Makefile
└── README.md
```