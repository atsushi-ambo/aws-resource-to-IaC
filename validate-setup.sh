#!/bin/bash

# Setup Validation Script
# Checks if all dependencies and prerequisites are met

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Status tracking
ERRORS=0
WARNINGS=0

log_success() { echo -e "${GREEN}✓${NC} $*"; }
log_error() { echo -e "${RED}✗${NC} $*"; ((ERRORS++)); }
log_warning() { echo -e "${YELLOW}⚠${NC} $*"; ((WARNINGS++)); }
log_info() { echo -e "${BLUE}ℹ${NC} $*"; }

echo -e "${BLUE}AWS to IaC Toolkit - Setup Validation${NC}"
echo "======================================="
echo

# Check required tools
echo "Checking dependencies..."

if command -v aws >/dev/null 2>&1; then
    AWS_VERSION=$(aws --version 2>&1 | head -1)
    log_success "AWS CLI found: $AWS_VERSION"

    # Check if AWS is configured
    if aws configure list >/dev/null 2>&1; then
        DEFAULT_REGION=$(aws configure get region 2>/dev/null || echo "not set")
        DEFAULT_PROFILE=$(aws configure list | grep -E "profile" | awk '{print $2}' | head -1 || echo "default")
        log_success "AWS CLI configured (Profile: $DEFAULT_PROFILE, Region: $DEFAULT_REGION)"

        # Test AWS connectivity
        if aws sts get-caller-identity >/dev/null 2>&1; then
            ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
            log_success "AWS connectivity verified (Account: $ACCOUNT_ID)"
        else
            log_error "AWS credentials not working - please run 'aws configure'"
        fi
    else
        log_error "AWS CLI not configured - please run 'aws configure'"
    fi
else
    log_error "AWS CLI not found - install from https://aws.amazon.com/cli/"
fi

if command -v jq >/dev/null 2>&1; then
    JQ_VERSION=$(jq --version)
    log_success "jq found: $JQ_VERSION"
else
    log_error "jq not found - install with: brew install jq (macOS) or apt install jq (Ubuntu)"
fi

echo

# Check script files
echo "Checking toolkit scripts..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQUIRED_SCRIPTS=(
    "discover-aws-resources.sh"
    "analyze-terraform-state.sh"
    "compare-resources.sh"
    "compare_us_east_1.sh"
    "extract_us_east_resources.sh"
    "aws-iac-toolkit.sh"
)

for script in "${REQUIRED_SCRIPTS[@]}"; do
    if [[ -f "$SCRIPT_DIR/$script" ]]; then
        if [[ -x "$SCRIPT_DIR/$script" ]]; then
            log_success "Script found and executable: $script"
        else
            log_warning "Script found but not executable: $script"
            log_info "  Fix with: chmod +x $script"
        fi
    else
        log_error "Required script missing: $script"
    fi
done

echo

# Check for state files
echo "Checking for Terraform state files..."

STATE_FILES=$(find . -maxdepth 1 -name "*.json" -type f ! -name "aws-resources-*" ! -name "terraform-resources-*" ! -name "unmanaged-*" 2>/dev/null | wc -l | tr -d ' ')

if [[ $STATE_FILES -gt 0 ]]; then
    log_success "Found $STATE_FILES Terraform state file(s)"
    find . -maxdepth 1 -name "*.json" -type f ! -name "aws-resources-*" ! -name "terraform-resources-*" ! -name "unmanaged-*" 2>/dev/null | sed 's/^/  - /'
else
    log_warning "No Terraform state files found in current directory"
    log_info "  Place your *.json state files here before running analysis"
fi

echo

# Check permissions
echo "Checking file permissions..."

if [[ -w . ]]; then
    log_success "Current directory is writable"
else
    log_error "Current directory is not writable - cannot create output files"
fi

echo

# Summary
echo "Validation Summary:"
echo "==================="

if [[ $ERRORS -eq 0 ]]; then
    if [[ $WARNINGS -eq 0 ]]; then
        log_success "All checks passed! Ready to use the toolkit."
        echo
        log_info "To get started, run: ./aws-iac-toolkit.sh workflow"
    else
        echo -e "${YELLOW}Setup mostly ready with $WARNINGS warning(s).${NC}"
        echo
        log_info "You can proceed, but consider fixing the warnings above."
    fi
else
    echo -e "${RED}Setup validation failed with $ERRORS error(s) and $WARNINGS warning(s).${NC}"
    echo
    log_info "Please fix the errors above before using the toolkit."
    exit 1
fi