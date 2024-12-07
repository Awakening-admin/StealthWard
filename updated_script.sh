#!/bin/bash

# Check if endpoint IP, user, and password are provided as arguments
if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "Usage: $0 <ENDPOINT_IP> <USER> <SUDO_PASSWORD>"
    exit 1
fi

ENDPOINT_IP="$1"
ENDPOINT_USER="$2"
ENDPOINT_PASSWORD="$3"
ADMIN_USER=$(whoami)

# Generate SSH Key if it does not already exist
if [ ! -f ~/.ssh/id_rsa ]; then
    echo "Generating SSH key..."
    ssh-keygen -t rsa -b 2048 -f ~/.ssh/id_rsa -N ""
else
    echo "SSH key already exists. Skipping key generation."
fi

# Copy SSH Key to the endpoint machine for passwordless access
echo "Copying SSH key to $ENDPOINT_USER@$ENDPOINT_IP..."

# Ensure .ssh directory exists on the remote endpoint
ssh $ENDPOINT_USER@$ENDPOINT_IP "mkdir -p ~/.ssh && chmod 700 ~/.ssh"

# Copy the public key to the remote endpoint's authorized_keys
ssh-copy-id -i ~/.ssh/id_rsa.pub $ENDPOINT_USER@$ENDPOINT_IP

# Verify key-based authentication
echo "Verifying SSH key-based login..."
ssh -o BatchMode=yes $ENDPOINT_USER@$ENDPOINT_IP "echo 'SSH setup successful for $ADMIN_USER on $ENDPOINT_IP'" || {
    echo "Error: Passwordless SSH setup failed. Please check the SSH configuration."
    exit 1
}

# Install dependencies on the endpoint
echo "Installing dependencies on the endpoint..."
ssh $ENDPOINT_USER@$ENDPOINT_IP <<EOF
    echo "$ENDPOINT_PASSWORD" | sudo -S apt-get update
    echo "$ENDPOINT_PASSWORD" | sudo -S apt-get install -y tcpdump libpcap-dev
EOF

# Create necessary directories on the endpoint (use sudo with -S for non-interactive)
echo "Setting up directories on the endpoint..."
ssh $ENDPOINT_USER@$ENDPOINT_IP <<EOF
    echo "$ENDPOINT_PASSWORD" | sudo -S mkdir -p /var/edr_agent/pcap_files
    echo "$ENDPOINT_PASSWORD" | sudo -S mkdir -p /var/edr_agent/logs
    echo "$ENDPOINT_PASSWORD" | sudo -S chown $ENDPOINT_USER:$ENDPOINT_USER /var/edr_agent /var/edr_agent/pcap_files /var/edr_agent/logs
    echo "$ENDPOINT_PASSWORD" | sudo -S chmod 700 /var/edr_agent /var/edr_agent/pcap_files /var/edr_agent/logs
EOF

# Confirm the setup
echo "Directory structure set up on $ENDPOINT_IP:"
ssh $ENDPOINT_USER@$ENDPOINT_IP "ls -ld /var/edr_agent /var/edr_agent/pcap_files /var/edr_agent/logs"

# Deploy agents to the endpoint
echo "Deploying agents to the endpoint..."
scp ./agent $ENDPOINT_USER@$ENDPOINT_IP:/var/edr_agent/agent
scp ./Lagent $ENDPOINT_USER@$ENDPOINT_IP:/var/edr_agent/Lagent

# Set permissions on the agent files
ssh $ENDPOINT_USER@$ENDPOINT_IP <<EOF
    echo "$ENDPOINT_PASSWORD" | sudo -S chmod +x /var/edr_agent/agent
    echo "$ENDPOINT_PASSWORD" | sudo -S chmod +x /var/edr_agent/Lagent
EOF

# Final confirmation
echo "Directory structure and agents deployed on $ENDPOINT_IP:"
ssh $ENDPOINT_USER@$ENDPOINT_IP "ls -ld /var/edr_agent /var/edr_agent/pcap_files /var/edr_agent/logs /var/edr_agent/agent /var/edr_agent/Lagent"

echo "Setup complete. Endpoint $ENDPOINT_IP is now ready with passwordless SSH, necessary directories, installed dependencies, and the deployed agents."
