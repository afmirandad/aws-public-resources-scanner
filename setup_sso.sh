#!/bin/bash

# AWS SSO Setup Script for Public Resources Scanner

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo "🔐 AWS SSO Setup for Public Resources Scanner"
echo "============================================="
echo

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    log_error "AWS CLI is not installed. Please install it first:"
    echo "https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
    exit 1
fi

log_success "AWS CLI found: $(aws --version)"

# Configure SSO
log_info "Starting AWS SSO configuration..."
echo

echo "You'll need the following information from your AWS SSO administrator:"
echo "- SSO start URL (e.g., https://my-company.awsapps.com/start)"
echo "- SSO region (e.g., us-east-1)"
echo "- Account ID"
echo "- Role name"
echo

read -p "Press Enter to continue with AWS SSO configuration..."

aws configure sso

echo
log_info "Listing available profiles..."
aws configure list-profiles

echo
read -p "Enter the profile name you want to use for scanning: " PROFILE_NAME

if [ -z "$PROFILE_NAME" ]; then
    log_error "Profile name cannot be empty"
    exit 1
fi

# Test the profile
log_info "Testing AWS SSO login with profile: $PROFILE_NAME"
aws sso login --profile "$PROFILE_NAME"

# Verify credentials
log_info "Verifying credentials..."
if aws sts get-caller-identity --profile "$PROFILE_NAME"; then
    log_success "✅ AWS SSO login successful!"
else
    log_error "❌ Failed to authenticate with AWS SSO"
    exit 1
fi

# Update .env file
log_info "Updating .env file with SSO profile..."
if [ -f ".env" ]; then
    # Update existing .env
    if grep -q "^AWS_PROFILE=" .env; then
        sed -i.bak "s/^AWS_PROFILE=.*/AWS_PROFILE=$PROFILE_NAME/" .env
    else
        echo "AWS_PROFILE=$PROFILE_NAME" >> .env
    fi
    
    # Comment out direct credentials if they exist
    sed -i.bak 's/^AWS_ACCESS_KEY_ID=/#AWS_ACCESS_KEY_ID=/' .env
    sed -i.bak 's/^AWS_SECRET_ACCESS_KEY=/#AWS_SECRET_ACCESS_KEY=/' .env
    sed -i.bak 's/^AWS_SESSION_TOKEN=/#AWS_SESSION_TOKEN=/' .env
else
    log_error ".env file not found. Creating one..."
    cp .env.example .env
    sed -i.bak "s/^AWS_PROFILE=.*/AWS_PROFILE=$PROFILE_NAME/" .env
fi

log_success "✅ Configuration completed!"
echo
echo "📋 Summary:"
echo "├─ Profile: $PROFILE_NAME"
echo "├─ .env file updated"
echo "└─ Ready to run scanner"
echo
echo "🚀 Next steps:"
echo "1. Run: ./run_scanner.sh"
echo "2. Or: docker-compose up --build"
echo
log_warning "Note: You may need to run 'aws sso login --profile $PROFILE_NAME' periodically when the session expires."
