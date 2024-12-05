# Use Alpine Linux with Python 3 as the base image
FROM python:3.12-alpine

# Set environment variables to prevent Python from buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=app.py

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file to the container
COPY requirements.txt /app/

# Install dependencies
RUN apk add --no-cache --virtual .build-deps gcc musl-dev libffi-dev openssl-dev && \
    pip install --no-cache-dir -r requirements.txt && \
    apk del .build-deps

# Copy the application code to the container
COPY . /app/ 
COPY website/ /app/website/

# Expose the application port
EXPOSE 5000

# Define the entry point
ENTRYPOINT ["python3"]

# Run Flask application
CMD ["-m", "flask", "run", "--host=0.0.0.0"]
