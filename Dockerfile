FROM python:3.13-slim-bullseye

# Install Poetry
RUN pip install --no-cache-dir poetry

# Set workdir
WORKDIR /app

# Copy Poetry files first for better caching
COPY pyproject.toml poetry.lock* ./

# Install dependencies (in-project venv)
RUN poetry config virtualenvs.in-project true \
    && poetry install --no-interaction --no-ansi --no-root

# Copy the rest of the app
COPY . .

# Set PATH for Poetry's virtualenv
ENV PATH="/app/.venv/bin:$PATH"

# Default command (adjust as needed)
CMD ["poetry", "run", "python", "src/pcap_analyser/cli.py"]
