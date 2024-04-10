# Use the official Python 3.7 base image
FROM python:3.7-slim

# Set environment variables for Python optimization
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Set the working directory in the container
WORKDIR /app

# Copy the virtual environment from the local .venv directory to the container
COPY .venv .venv

# Set the path to the virtual environment
ENV PATH="/app/.venv/bin:$PATH"

# Copy the entire project directory into the container
COPY . .

RUN pip install -r requirements.txt

EXPOSE 8080

# Command to run your Python application
CMD ["python", "app.py"]
