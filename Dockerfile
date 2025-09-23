FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -e .

# Create directory for backups and logs
RUN mkdir -p backups logs

# Create volume mount points
VOLUME ["/app/backups", "/app/logs"]

# Default configuration through environment variables
ENV MAX_INPUT_LENGTH=10000 \
    MAX_BATCH_SIZE=1000 \
    MAX_QUERY_LENGTH=500 \
    BACKUP_COUNT=5 \
    BACKUP_INTERVAL=86400 \
    LOG_LEVEL=INFO

# Run as non-root user
RUN useradd -m nexususer
RUN chown -R nexususer:nexususer /app
USER nexususer

# Command to run the service
CMD ["python", "-m", "nexus_signal_engine"]