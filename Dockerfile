# Use Kali Linux as the base image
FROM kalilinux/kali-rolling

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update and install system dependencies (Pentesting Tools + Python)
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    nmap \
    subfinder \
    httpx-toolkit \
    nuclei \
    feroxbuster \
    wpscan \
    hydra \
    testssl.sh \
    curl \
    netcat-traditional \
    git \
    && rm -rf /var/lib/apt/lists/*

# Pre-update wpscan database
RUN wpscan --update

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies globally (safe within a container context)
# Using --break-system-packages for modern Debian/Kali compliance
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Create the clients directory to ensure it exists for volume mounting
RUN mkdir -p clients

# Copy the rest of the application code
COPY . .

# Ensure signal handling works correctly (Forwarding SIGINT)
STOPSIGNAL SIGINT

# Expose the web GUI port
EXPOSE 1337

# Set the default command to run the web GUI
# Users can still run the CLI by overriding the entrypoint target
ENTRYPOINT ["python3", "web_app.py"]
