FROM python:3.11-slim

WORKDIR /app

# Install system build dependencies required for compiling libraries (like psycopg2 or numpy/xgboost if needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application files
COPY . .

# Render/Railway will dynamically supply the PORT environment variable.
# We set host to 0.0.0.0 so the application accepts traffic routed from outside the container.
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}
