#!/bin/bash

# Railway Entrypoint Script for AWS Public Resources Scanner
# This script validates AWS credentials and starts the scanner

echo "🚀 Starting AWS Public Resources Scanner on Railway..."

# Function to check if variable is set and not empty
check_var() {
    local var_name=$1
    local var_value=$2
    
    if [ -z "$var_value" ]; then
        echo "❌ Environment variable $var_name is not set or empty"
        return 1
    else
        echo "✅ $var_name is configured"
        return 0
    fi
}

# Function to validate AWS credentials
validate_aws_credentials() {
    echo "🔐 Validating AWS credentials..."
    
    # Check if using SSO profile
    if [ -n "$AWS_PROFILE" ]; then
        echo "📋 Using AWS SSO Profile: $AWS_PROFILE"
        
        # Check if all SSO variables are set
        if [ -n "$AWS_SSO_START_URL" ] && [ -n "$AWS_SSO_REGION" ] && [ -n "$AWS_SSO_ACCOUNT_ID" ] && [ -n "$AWS_SSO_ROLE_NAME" ]; then
            echo "✅ AWS SSO environment variables are configured"
            
            # Create AWS config directory
            mkdir -p ~/.aws
            
            # Create AWS config file for SSO
            cat > ~/.aws/config << EOF
[profile $AWS_PROFILE]
sso_start_url = $AWS_SSO_START_URL
sso_region = $AWS_SSO_REGION
sso_account_id = $AWS_SSO_ACCOUNT_ID
sso_role_name = $AWS_SSO_ROLE_NAME
region = ${AWS_DEFAULT_REGION:-us-east-1}
output = json
EOF
            echo "✅ AWS SSO config file created"
        else
            echo "❌ SSO profile specified but SSO environment variables are missing"
            echo "Required: AWS_SSO_START_URL, AWS_SSO_REGION, AWS_SSO_ACCOUNT_ID, AWS_SSO_ROLE_NAME"
            return 1
        fi
    else
        # Check direct credentials
        echo "🔑 Using direct AWS credentials"
        
        if ! check_var "AWS_ACCESS_KEY_ID" "$AWS_ACCESS_KEY_ID"; then
            return 1
        fi
        
        if ! check_var "AWS_SECRET_ACCESS_KEY" "$AWS_SECRET_ACCESS_KEY"; then
            return 1
        fi
        
        # Session token is optional
        if [ -n "$AWS_SESSION_TOKEN" ]; then
            echo "✅ AWS_SESSION_TOKEN is configured (temporary credentials)"
        fi
    fi
    
    # Validate default region
    if ! check_var "AWS_DEFAULT_REGION" "$AWS_DEFAULT_REGION"; then
        echo "⚠️  AWS_DEFAULT_REGION not set, using us-east-1"
        export AWS_DEFAULT_REGION=us-east-1
    fi
    
    # Test AWS connection
    echo "🧪 Testing AWS credentials..."
    
    if [ -n "$AWS_PROFILE" ]; then
        # For SSO, we need to assume the credentials are valid
        # since we can't login interactively in a container
        echo "⚠️  SSO profile configured - assuming credentials are valid"
        echo "Note: Make sure you've configured the SSO token externally"
    else
        # Test direct credentials
        if aws sts get-caller-identity >/dev/null 2>&1; then
            echo "✅ AWS credentials validated successfully"
            aws sts get-caller-identity
        else
            echo "❌ Credential check failed"
            echo "Please verify your AWS credentials are correct and have sufficient permissions"
            return 1
        fi
    fi
    
    return 0
}

# Main execution
echo "==========================================="
echo "🌐 AWS Public Resources Scanner - Railway"
echo "==========================================="

# Validate environment
if ! validate_aws_credentials; then
    echo "❌ Failed to validate AWS credentials"
    exit 1
fi

# Show configuration
echo ""
echo "📊 Configuration Summary:"
echo "- AWS Region: ${AWS_DEFAULT_REGION}"
echo "- Log Level: ${LOG_LEVEL:-INFO}"
echo "- Max Workers: ${MAX_WORKERS:-10}"
echo "- Services to Scan: ${SERVICES_TO_SCAN:-ec2,rds,elb,s3}"
echo "- Timeout: ${TIMEOUT_SECONDS:-30} seconds"

echo ""
echo "🚀 Starting scanner..."
echo "==========================================="

# Start the main application
exec python main.py
