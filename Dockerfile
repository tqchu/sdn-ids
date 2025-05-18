FROM python:3.9-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc python3-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY detector/ /app/detector/
COPY alerter/ /app/alerter/
COPY models/ /app/models/

# Set environment variables
ENV PYTHONPATH=/app

# Command to run the application
CMD ["python3", "-u", "-m", "detector.consumer"]