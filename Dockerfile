# CodeMender ADK Agent Production Containerfile
FROM python:3.14-slim

WORKDIR /app

# Install system utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl sqlite3 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONPATH=/app
ENV CODEMENDER_DB_PATH=/app/codemender_state.db

EXPOSE 8080

CMD ["python", "-m", "codemender_agent.cicd.ci_scanner", "--repo-path", "."]
