FROM python:3.12-slim

# Install system dependencies needed for YARA-python build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Expose standard Flask port
EXPOSE 5000

# Command to run the application
CMD ["python", "app.py"]
