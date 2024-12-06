# Use Alpine Linux with Python 3 as the base image
FROM python:3.12.0-alpine

# Set environment variables to prevent Python from buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_APP=app.py \
    FLASK_RUN_HOST=0.0.0.0

# Install runtime and build dependencies
RUN apk update && apk add --no-cache \
    perl wireshark-common libffi openssl && \
    perl -v && text2pcap -v && \
    apk add --no-cache --virtual .build-deps gcc musl-dev libffi-dev openssl-dev && \
    apk del .build-deps

# Create and switch to a non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# Set the working directory in the container
WORKDIR /app

# Copy dependencies first to leverage caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the application port
EXPOSE 5000

# Run Flask application
CMD ["python3", "-m", "flask", "run", "--host=0.0.0.0"]