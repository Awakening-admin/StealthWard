#!/bin/bash

# Check if endpoint IP, user, and password are provided
if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "Usage: $0 <ENDPOINT_IP> <USER> <PASSWORD>"
    exit 1
fi

ENDPOINT_IP="$1"
ENDPOINT_USER="$2"
ENDPOINT_PASSWORD="$3"

echo "Connecting to $ENDPOINT_USER@$ENDPOINT_IP to clean old SSH entries..."

# Use ssh with -t for allocating a pseudo-terminal, and use sudo -t for interactive sudo
ssh -t $ENDPOINT_USER@$ENDPOINT_IP <<EOF
    # Run the clean-up commands inside the remote session using sudo with a PTY
    sudo -v # This will prompt for the sudo password

    echo "Cleaning up old SSH key entries..."

    if [ -f ~/.ssh/authorized_keys ]; then
        echo "Backing up existing authorized_keys file..."
        mv ~/.ssh/authorized_keys ~/.ssh/authorized_keys.bak
        echo "Old authorized_keys file backed up as ~/.ssh/authorized_keys.bak"
    else
        echo "No authorized_keys file found. Nothing to clean."
    fi
EOF

# Confirm completion
echo "Old SSH key entries cleaned up on $ENDPOINT_IP."
