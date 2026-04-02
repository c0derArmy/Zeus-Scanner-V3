# Zeus Scanner - Updated Docker Configuration
# Compatible with modern Python and dependencies

FROM python:3.11-slim

LABEL maintainer="Zeus Scanner Team"
LABEL description="Zeus Scanner - Advanced Web Vulnerability Assessment Tool"
LABEL version="1.5.2"

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive

# Create app directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    # Core system packages
    wget \
    curl \
    git \
    unzip \
    gnupg \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    # Build tools
    build-essential \
    gcc \
    g++ \
    # Network tools
    nmap \
    sqlmap \
    # Browser and display
    firefox-esr \
    xvfb \
    # Python development
    python3-dev \
    python3-pip \
    python3-venv \
    # XML/HTML processing
    libxml2-dev \
    libxslt1-dev \
    # SSL/TLS
    libssl-dev \
    libffi-dev \
    # Image processing
    libjpeg-dev \
    libpng-dev \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install GeckoDriver for Selenium
RUN GECKODRIVER_VERSION=v0.36.0 && \
    wget -O /tmp/geckodriver.tar.gz "https://github.com/mozilla/geckodriver/releases/download/${GECKODRIVER_VERSION}/geckodriver-${GECKODRIVER_VERSION}-linux64.tar.gz" && \
    tar -xzf /tmp/geckodriver.tar.gz -C /tmp && \
    chmod +x /tmp/geckodriver && \
    mv /tmp/geckodriver /usr/local/bin/ && \
    rm /tmp/geckodriver.tar.gz

# Copy application files
COPY . /app/

# Create virtual environment and install Python dependencies
RUN python3 -m venv /app/myvenv && \
    /app/myvenv/bin/pip install --upgrade pip setuptools wheel && \
    /app/myvenv/bin/pip install -r /app/requirements.txt

# Set up Firefox for headless operation
RUN mkdir -p /root/.mozilla/firefox && \
    echo 'user_pref("browser.display.use_system_colors", true);' > /root/.mozilla/firefox/prefs.js

# Create necessary directories
RUN mkdir -p /app/log /app/log/blackwidow-log /app/log/url-log /app/log/blacklist

# Set permissions
RUN chmod +x /app/zeus.py && \
    chmod -R 755 /app/

# Expose ports (if needed for web interface)
EXPOSE 8080 8775

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 --version || exit 1

# Set the entrypoint
ENTRYPOINT ["/app/myvenv/bin/python", "/app/zeus.py"]

# Default command (show help)
CMD ["--help"]

