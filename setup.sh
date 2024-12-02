#!/bin/bash

# Check if admin user and IP are provided as arguments
if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $0 <ADMIN_USER> <ADMIN_IP>"
    exit 1
fi

ADMIN_USER="$1"
ADMIN_IP="$2"

# Generate SSH Key if it does not already exist
if [ ! -f ~/.ssh/id_rsa ]; then
    echo "Generating SSH key..."
    ssh-keygen -t rsa -b 2048 -f ~/.ssh/id_rsa -N ""
else
    echo "SSH key already exists. Skipping key generation."
fi

# Copy SSH Key to the admin machine for passwordless access
echo "Copying SSH key to $ADMIN_USER@$ADMIN_IP..."
ssh-copy-id -i ~/.ssh/id_rsa.pub $ADMIN_USER@$ADMIN_IP

# Verify key-based authentication
echo "Verifying SSH key-based login..."
ssh -o BatchMode=yes $ADMIN_USER@$ADMIN_IP "echo 'SSH setup successful for $ADMIN_USER@$ADMIN_IP'" || {
    echo "Error: Passwordless SSH setup failed. Please check the SSH configuration."
    exit 1
}

# Create necessary directories on both the endpoint and admin machine
echo "Setting up directories on endpoint and admin machine..."

# Create directories on endpoint (local machine)
sudo mkdir -p /var/edr_agent
sudo chown $USER:$USER /var/edr_agent
sudo chmod 700 /var/edr_agent

# Create directories on admin machine (remote machine)
ssh $ADMIN_USER@$ADMIN_IP "mkdir -p /home/robot/edr_server/pcap_files"
ssh $ADMIN_USER@$ADMIN_IP "chmod 700 /home/robot/edr_server/pcap_files"
ssh $ADMIN_USER@$ADMIN_IP "chown $ADMIN_USER:$ADMIN_USER /home/robot/edr_server/pcap_files"

echo "Setup complete. Passwordless SSH is now configured and directories are created with proper permissions."
