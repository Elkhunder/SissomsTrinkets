#!/bin/bash

# Mac SSH Setup Script for Windows Connections
# Supports both IP addresses and FQDNs
# Usage: ./setup_mac_ssh.sh [windows-username] [windows-ip-or-hostname]

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Encryption 
IDENTITY_KEY_TYPE='ed25519'
IDENTITY_KEY_PATH="${HOME}/.ssh/id_ed25519"
IDENTITY_KEY_FILE="${IDENTITY_KEY_PATH}.pub"

# Check if script is run with -h or --help
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    echo -e "${GREEN}Mac SSH Setup Script for Windows Connections${NC}"
    echo "Usage: $0 [windows-username] [windows-ip-or-hostname]"
    echo "If no arguments are provided, the script will prompt for them."
    exit 0
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to validate host (IP or FQDN)
validate_host() {
    local host=$1
    # Check if it's a valid IP
    if [[ $host =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 0
    fi
    # Check if it's a valid FQDN
    if [[ $host =~ ^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)+([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$ ]]; then
        return 0
    fi
    return 1
}

# Function to copy SSH key to Windows
copy_key_to_windows() {
    echo -e "${BLUE}Attempting to copy SSH key to Windows...${NC}"
    
    # Check if we have a public key
    if [ ! -f "$IDENTITY_KEY_FILE" ]; then
        echo -e "${YELLOW}No public key found at ${IDENTITY_KEY_FILE}${NC}"
        return 1
    fi

    # Prepare the key for transfer (escape special characters)
    KEY_CONTENT=$(sed 's/"/\\"/g; s/\\/\\\\/g' "$IDENTITY_KEY_FILE")
    KEY_FINGERPRINT=$(ssh-keygen -lf "$IDENTITY_KEY_FILE" | awk '{print $2}')

    # PowerShell command to check and add key to Windows
    PS_COMMAND="@'
    \$key = \"$KEY_CONTENT\"
    \$keyFingerprint = \"$KEY_FINGERPRINT\"
    \$sshDir = \"\$env:USERPROFILE\.ssh\"
    \$authKeys = \"\$sshDir\authorized_keys\"
    
    # Create directory if it doesn't exist
    if (-not (Test-Path \$sshDir)) { New-Item -ItemType Directory -Path \$sshDir -Force }
    
    # Check if key already exists
    \$keyExists = \$false
    if (Test-Path \$authKeys) {
        \$existingKeys =  ssh-keygen -l -f \$authKeys
        foreach (\$existingKey in \$existingKeys) {
            try {
                \$keyParts = \$existingKey -split ' '
                if (\$keyParts.Count -ge 2) {
                    \$fingerPrint = \$keyParts[1]
                    # Simple comparison of the key data portion
                    if (\$fingerPrint -eq \$keyFingerprint) {
                        \$keyExists = \$true
                        break
                    }
                }
            } catch {
                # Skip malformed keys
                continue
            }
        }
    }
    
    if (-not \$keyExists) {
        Add-Content -Path \$authKeys -Value \$key -Force
        icacls \$authKeys /inheritance:r /grant \"Administrators:F\" /grant \"SYSTEM:F\"
        Write-Output \"SUCCESS: Key added to authorized_keys\"
        exit 0
    } else {
        Write-Output \"NOTICE: Key already exists in authorized_keys\"
        exit 1
    }
'@"

    # Execute remotely
    echo -e "${YELLOW}You may need to enter your Windows password for initial setup${NC}"
    OUTPUT=$(ssh "$WINDOWS_USER@$WINDOWS_HOST" "powershell -Command $PS_COMMAND" 2>&1)
    STATUS=$?
    
    if [[ "$OUTPUT" == *"SUCCESS: Key added to authorized_keys"* ]]; then
        echo -e "${GREEN}Successfully copied SSH key to Windows!${NC}"
        return 0
    elif [[ "$OUTPUT" == *"NOTICE: Key already exists in authorized_keys"* ]]; then
        echo -e "${BLUE}SSH key already present on Windows. No changes made.${NC}"
        return 0
    else
        echo -e "${YELLOW}Automatic copy failed. Manual steps:${NC}"
        echo "1. Copy this key:"
        cat "$IDENTITY_KEY_FILE"
        echo -e "\n2. Add it to: C:\Users\\$WINDOWS_USER\.ssh\authorized_keys on your Windows machine"
        echo "3. Ensure the file has strict permissions (only SYSTEM and Administrators should have access)"
        return 1
    fi
}

# Check for required commands
for cmd in ssh ssh-keygen ssh-copy-id scp dig; do
    if ! command_exists "$cmd"; then
        echo -e "${RED}Error: $cmd is not installed.${NC}"
        if [[ "$cmd" == "dig" ]]; then
            echo "Install dig with: brew install bind" # For macOS
        else
            echo "Please install OpenSSH client tools."
        fi
        exit 1
    fi
done

# Get Windows connection info
if [ $# -ge 2 ]; then
    WINDOWS_USER="$1"
    WINDOWS_HOST="$2"
else
    echo -e "${YELLOW}Enter Windows connection details:${NC}"
    read -rp "Windows username: " WINDOWS_USER
    read -rp "Windows IP address or hostname: " WINDOWS_HOST
fi

# Validate host format
if ! validate_host "$WINDOWS_HOST"; then
    echo -e "${RED}Error: Invalid host format. Please use an IP address or fully qualified domain name.${NC}"
    exit 1
fi

# Resolve host to IP for testing (but keep original host for SSH config)
RESOLVED_IP=$(dig +short "$WINDOWS_HOST" | head -n 1)
if [[ -z "$RESOLVED_IP" ]]; then
    # If dig didn't resolve it, assume it's an IP
    RESOLVED_IP="$WINDOWS_HOST"
fi

# Check if we can ping the Windows machine
echo -e "${BLUE}Testing connection to Windows machine ($RESOLVED_IP)...${NC}"
if ! ping -c 2 "$RESOLVED_IP" &> /dev/null; then
    echo -e "${RED}Error: Could not ping $RESOLVED_IP${NC}"
    echo "Please ensure:"
    echo "1. The Windows machine is powered on and connected to the network"
    echo "2. Both machines are on the same network"
    echo "3. There are no firewall blocks on the network"
    echo "4. The hostname resolves correctly (if using FQDN)"
    exit 1
fi

# Check SSH basic connectivity
echo -e "${BLUE}Testing SSH port (22) on Windows machine ($WINDOWS_HOST)...${NC}"
if ! nc -z -G 2 "$WINDOWS_HOST" 22 &> /dev/null; then
    echo -e "${RED}Error: Could not connect to port 22 on $WINDOWS_HOST${NC}"
    echo "Please ensure:"
    echo "1. OpenSSH Server is installed on Windows"
    echo "2. The SSH service is running"
    echo "3. Windows Firewall allows inbound connections on port 22"
    echo "4. The hostname resolves correctly (if using FQDN)"
    exit 1
fi

# Generate SSH keys if they don't exist
echo -e "${BLUE}Checking for existing SSH keys...${NC}"
if [ ! -f "${IDENTITY_KEY_PATH}" ]; then
    echo -e "${YELLOW}No SSH key found. Generating a new ED25519 key...${NC}"
    ssh-keygen -t $IDENTITY_KEY_TYPE -f "${IDENTITY_KEY_PATH}" -N "" -q
    echo -e "${GREEN}SSH key generated at ${IDENTITY_KEY_PATH}${NC}"
else
    echo -e "${GREEN}Existing SSH key found at ${IDENTITY_KEY_PATH}.${NC}"
fi

# Configure SSH client settings
echo -e "${BLUE}Configuring SSH client settings...${NC}"
if [ ! -f ~/.ssh/config ]; then
    touch ~/.ssh/config
    chmod 600 ~/.ssh/config
fi

# Create a unique Host identifier by replacing dots with underscores
HOST_IDENTIFIER="${WINDOWS_HOST%%[.]*}"

if ! grep -q "Host $HOST_IDENTIFIER" ~/.ssh/config; then
    cat >> ~/.ssh/config <<EOF

Host $HOST_IDENTIFIER
    HostName $WINDOWS_HOST
    User $WINDOWS_USER
    IdentityFile $IDENTITY_KEY_PATH
    ServerAliveInterval 60
    TCPKeepAlive yes
EOF
    echo -e "${GREEN}Added Windows SSH configuration to ~/.ssh/config${NC}"
    echo -e "You can now connect using: ${BLUE}ssh $HOST_IDENTIFIER${NC}"
else
    echo -e "${YELLOW}Windows SSH configuration already exists in ~/.ssh/config${NC}"
fi

# Copy SSH key to Windows
copy_key_to_windows

# Test SSH connection
echo -e "${BLUE}Testing SSH connection to Windows...${NC}"
if ssh -o "BatchMode=yes" -o "ConnectTimeout=5" "$WINDOWS_USER@$WINDOWS_HOST" "Write-Output \"SSH connection successful!\""; then
    echo -e "${GREEN}SSH setup complete! You can now connect using:${NC}"
    echo -e "  ${BLUE}ssh $HOST_IDENTIFIER${NC} (using the host alias)"
    echo -e "  ${BLUE}ssh $WINDOWS_USER@$WINDOWS_HOST${NC} (direct connection)"
else
    echo -e "${RED}SSH connection test failed.${NC}"
    echo "Possible issues:"
    echo "1. Key-based authentication not properly configured on Windows"
    echo "2. Windows SSH server configuration needs adjustment"
    echo "3. Network/firewall issues"
    echo "4. Hostname resolution problems (if using FQDN)"
    exit 1
fi

# Optional: Add Windows host to known_hosts
echo -e "${BLUE}Adding Windows host to known_hosts...${NC}"
ssh-keyscan -H "$WINDOWS_HOST" >> ~/.ssh/known_hosts 2>/dev/null

echo -e "${GREEN}Mac SSH setup completed successfully!${NC}"