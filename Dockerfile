# Use Python 3.7 base image
FROM python:3.7

# Set environment variables
ENV PYTHONUNBUFFERED 1

# Install SSH server and essential build tools
RUN apt-get update && \
    apt-get install -y openssh-server \
                       build-essential

# Create SSH directory
RUN mkdir /var/run/sshd

# Set root password (change 'rootpassword' to your secure password)
RUN echo 'root:rootpassword' | chpasswd

# Allow SSH root login
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Expose SSH port
EXPOSE 22

# Set work directory
WORKDIR /app

# Copy requirements.txt and install dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Start SSH server
CMD ["/usr/sbin/sshd", "-D"]
