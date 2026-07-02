FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY uahp ./uahp
COPY polis ./polis
COPY csp ./csp
COPY demos ./demos

RUN pip install --no-cache-dir -e ".[registry]"

CMD ["python3", "demos/agent_node.py"]
