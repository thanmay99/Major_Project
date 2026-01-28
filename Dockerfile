FROM python:3.8-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Install compatible versions
RUN pip install "eventlet==0.30.2"
RUN pip install "ryu==4.34" networkx flask requests

# Create app directory
WORKDIR /app

# Copy your files - USING CORRECT FILENAME
COPY congestion_aware_controller_modified.py .
COPY blockchain_service.py .

# Expose ports
EXPOSE 5000 6633 6653

# Start both services - USING CORRECT FILENAME
CMD ["sh", "-c", "echo '🚀 Starting Blockchain Service...' && python blockchain_service.py & echo '⏳ Waiting for blockchain service...' && sleep 5 && echo '🎯 Starting Ryu Controller...' && ryu-manager congestion_aware_controller_modified.py --observe-links"]