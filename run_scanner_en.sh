#!/bin/bash

# Script to run the AWS public resources scanner
# This script handles Docker container configuration and execution

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to display messages
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

# Check if Docker is available
check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker is not running. Is the Docker daemon started?"
        exit 1
    fi
    
    log_success "Docker is available"
}

# Check if .env file exists
check_env_file() {
    if [ ! -f ".env" ]; then
        log_warning ".env file not found"
        log_info "Creating .env from .env.example..."
        
        if [ -f ".env.example" ]; then
            cp .env.example .env
            log_warning "Please edit the .env file with your AWS credentials before continuing"
            log_info "Editing .env..."
            ${EDITOR:-nano} .env
        else
            log_error ".env.example file not found"
            exit 1
        fi
    else
        log_success ".env file found"
    fi
}

# Check credentials in .env
check_credentials() {
    local has_key=$(grep -c "^AWS_ACCESS_KEY_ID=" .env 2>/dev/null || echo "0")
    local has_secret=$(grep -c "^AWS_SECRET_ACCESS_KEY=" .env 2>/dev/null || echo "0")
    
    if [ "$has_key" -eq 0 ] || [ "$has_secret" -eq 0 ]; then
        log_error "AWS credentials not configured in .env"
        log_info "Make sure to configure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
        exit 1
    fi
    
    # Check that they are not empty
    source .env
    if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
        log_error "AWS credentials are empty in .env"
        exit 1
    fi
    
    log_success "AWS credentials configured"
}

# Build Docker image
build_image() {
    log_info "Building Docker image..."
    docker build -t aws-public-scanner . || {
        log_error "Error building Docker image"
        exit 1
    }
    log_success "Docker image built successfully"
}

# Create logs directory
create_logs_dir() {
    if [ ! -d "logs" ]; then
        mkdir -p logs
        log_info "Logs directory created"
    fi
}

# Run scanner
run_scanner() {
    log_info "Running AWS public resources scanner..."
    log_info "Logs will be displayed in real time..."
    echo
    
    docker run --rm \
        --env-file .env \
        -v "$(pwd)/logs:/app/logs" \
        aws-public-scanner || {
        log_error "Error running scanner"
        exit 1
    }
    
    echo
    log_success "Scanner completed"
}

# Show results
show_results() {
    local latest_report=$(ls -t logs/public_resources_report_*.json 2>/dev/null | head -n1)
    
    if [ -n "$latest_report" ]; then
        log_info "Latest report: $latest_report"
        
        # Extract basic statistics from JSON
        local total_resources=$(jq -r '.total_resources_scanned // "N/A"' "$latest_report" 2>/dev/null)
        local public_resources=$(jq -r '.public_resources_found // "N/A"' "$latest_report" 2>/dev/null)
        
        echo
        echo "📊 SCAN SUMMARY:"
        echo "├─ Total resources scanned: $total_resources"
        echo "├─ Public resources found: $public_resources"
        echo "└─ Report saved to: $latest_report"
        echo
        
        if [ "$public_resources" != "0" ] && [ "$public_resources" != "N/A" ]; then
            log_warning "⚠️  Public resources found. Check the report for details."
        else
            log_success "✅ Excellent! No public resources found."
        fi
    else
        log_warning "No result reports found"
    fi
}

# Help function
show_help() {
    echo "AWS Public Resources Scanner"
    echo ""
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  help, -h, --help     Show this help"
    echo "  build               Only build Docker image"
    echo "  run                 Only run (assumes image already exists)"
    echo "  setup               Only verify configuration"
    echo "  logs                Show logs from last scan"
    echo ""
    echo "Without arguments, runs the complete process: verification + build + execution"
}

# Show logs
show_logs() {
    local latest_log=$(ls -t logs/*.log 2>/dev/null | head -n1)
    
    if [ -n "$latest_log" ]; then
        log_info "Showing logs from file: $latest_log"
        echo
        tail -50 "$latest_log"
    else
        log_warning "No log files found"
    fi
}

# Main function
main() {
    echo "🔍 AWS Public Resources Scanner"
    echo "================================="
    echo
    
    case "${1:-}" in
        "help"|"-h"|"--help")
            show_help
            exit 0
            ;;
        "build")
            check_docker
            build_image
            log_success "Build completed"
            exit 0
            ;;
        "run")
            check_docker
            check_env_file
            check_credentials
            create_logs_dir
            run_scanner
            show_results
            exit 0
            ;;
        "setup")
            check_docker
            check_env_file
            check_credentials
            log_success "Configuration verified successfully"
            exit 0
            ;;
        "logs")
            show_logs
            exit 0
            ;;
        "")
            # Complete process
            check_docker
            check_env_file
            check_credentials
            create_logs_dir
            build_image
            run_scanner
            show_results
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"
