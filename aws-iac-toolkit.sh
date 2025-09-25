#!/bin/bash

# AWS to IaC Toolkit - Main Orchestration Script
# Provides guided workflow for discovering and analyzing AWS resources

set -euo pipefail

# Configuration
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_step() { echo -e "${CYAN}[STEP]${NC} $*"; }

# Usage function
show_usage() {
    cat << EOF
${CYAN}AWS to Infrastructure as Code (IaC) Toolkit${NC}

Usage: $SCRIPT_NAME [COMMAND] [OPTIONS]

Commands:
    discover    Discover AWS resources in your account
    analyze     Analyze Terraform state files
    compare     Compare AWS resources vs Terraform managed resources
    workflow    Run guided workflow (discover -> analyze -> compare)
    help        Show this help message

Examples:
    $SCRIPT_NAME workflow                    # Run complete guided workflow
    $SCRIPT_NAME discover production         # Discover resources in production profile
    $SCRIPT_NAME analyze                     # Analyze all Terraform state files
    $SCRIPT_NAME compare                     # Compare latest discovery and analysis

For detailed help on each command, run:
    $SCRIPT_NAME <command> --help

EOF
}

# Check if script exists and is executable
check_script() {
    local script="$1"
    if [[ ! -f "$SCRIPT_DIR/$script" ]]; then
        log_error "Script not found: $script"
        return 1
    fi
    if [[ ! -x "$SCRIPT_DIR/$script" ]]; then
        log_error "Script not executable: $script"
        log_info "Run: chmod +x $SCRIPT_DIR/$script"
        return 1
    fi
    return 0
}

# Run guided workflow
run_workflow() {
    log_step "Starting AWS to IaC Discovery Workflow"
    echo

    # Step 1: Discover AWS resources
    log_step "Step 1/3: Discovering AWS resources..."
    if ! check_script "discover-aws-resources.sh"; then
        return 1
    fi

    echo -n "Enter AWS profile to use (default): "
    read -r profile
    profile=${profile:-default}

    echo -n "Enter AWS region (leave empty for profile default): "
    read -r region

    if [[ -n "$region" ]]; then
        "$SCRIPT_DIR/discover-aws-resources.sh" "$profile" "$region"
    else
        "$SCRIPT_DIR/discover-aws-resources.sh" "$profile"
    fi

    echo
    log_info "AWS resource discovery completed"

    # Step 2: Analyze Terraform state
    log_step "Step 2/3: Analyzing Terraform state files..."
    if ! check_script "analyze-terraform-state.sh"; then
        return 1
    fi

    log_info "Looking for Terraform state files in current directory..."
    state_files=$(find . -maxdepth 1 -name "*.json" -type f ! -name "aws-resources-*" ! -name "terraform-resources-*" ! -name "unmanaged-*" 2>/dev/null | wc -l)

    if [[ $state_files -eq 0 ]]; then
        log_warn "No Terraform state files found"
        log_info "Please place your Terraform state files (*.json) in the current directory"
        echo -n "Press Enter to continue when ready, or Ctrl+C to exit: "
        read -r
    fi

    "$SCRIPT_DIR/analyze-terraform-state.sh"

    echo
    log_info "Terraform state analysis completed"

    # Step 3: Compare resources
    log_step "Step 3/3: Comparing AWS resources vs Terraform managed resources..."
    if ! check_script "compare-resources.sh"; then
        return 1
    fi

    "$SCRIPT_DIR/compare-resources.sh"

    echo
    log_step "Workflow completed successfully!"
    echo
    log_info "Generated files:"
    echo "  📄 Text reports: $(find . -name "*-$(date +%Y%m%d)-*.txt" 2>/dev/null | head -3 | tr '\n' ' ')"
    echo "  📊 JSON data: $(find . -name "*-$(date +%Y%m%d)-*.json" 2>/dev/null | head -3 | tr '\n' ' ')"
    echo
    log_info "Next steps:"
    echo "  1. Review the unmanaged-resources-*.txt file"
    echo "  2. Plan your Terraform import strategy"
    echo "  3. Use terraform import commands for unmanaged resources"
}

# Handle command line arguments
case "${1:-help}" in
    discover)
        shift
        if ! check_script "discover-aws-resources.sh"; then exit 1; fi
        "$SCRIPT_DIR/discover-aws-resources.sh" "$@"
        ;;
    analyze)
        shift
        if ! check_script "analyze-terraform-state.sh"; then exit 1; fi
        "$SCRIPT_DIR/analyze-terraform-state.sh" "$@"
        ;;
    compare)
        shift
        if ! check_script "compare-resources.sh"; then exit 1; fi
        "$SCRIPT_DIR/compare-resources.sh" "$@"
        ;;
    workflow)
        run_workflow
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        log_error "Unknown command: ${1:-}"
        echo
        show_usage
        exit 1
        ;;
esac