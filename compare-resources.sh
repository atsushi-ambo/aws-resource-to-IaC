#!/bin/bash

# Resource Comparison Script
# Compares AWS resources with Terraform-managed resources to find unmanaged items

set -euo pipefail

# Configuration
SCRIPT_NAME="$(basename "$0")"
LOG_LEVEL="INFO"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_debug() { [[ "$LOG_LEVEL" == "DEBUG" ]] && echo -e "${BLUE}[DEBUG]${NC} $*" >&2; }
log_info() { echo -e "${GREEN}[INFO]${NC} $*" >&2; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Usage function
show_usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS] [AWS_JSON] [TERRAFORM_JSON]

Compare AWS resources with Terraform-managed resources to identify unmanaged resources.

Arguments:
    AWS_JSON        Path to AWS resources JSON file (auto-detected if not specified)
    TERRAFORM_JSON  Path to Terraform resources JSON file (auto-detected if not specified)

Options:
    -h, --help      Show this help message
    -v, --verbose   Enable verbose logging
    --no-color      Disable colored output

Examples:
    $SCRIPT_NAME                                    # Auto-detect latest files
    $SCRIPT_NAME aws.json terraform.json           # Use specific files
    $SCRIPT_NAME -v                                 # Verbose auto-detection

Output:
    unmanaged-resources-YYYYMMDD-HHMMSS.txt       # List of unmanaged resources

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            exit 0
            ;;
        -v|--verbose)
            LOG_LEVEL="DEBUG"
            shift
            ;;
        --no-color)
            RED='' GREEN='' YELLOW='' BLUE='' NC=''
            shift
            ;;
        -*)
            log_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

# Check dependencies
if ! command -v jq >/dev/null 2>&1; then
    log_error "jq is not installed. Please install it first:"
    echo "  brew install jq (macOS) or apt install jq (Ubuntu)"
    exit 1
fi

# Parse remaining arguments
AWS_JSON="${1:-}"
TF_JSON="${2:-}"

# Auto-detect files if not specified
if [[ -z "$AWS_JSON" ]]; then
    log_info "Auto-detecting AWS resources file..."
    AWS_JSON=$(find . -name "aws-resources-*.json" -type f -exec ls -t {} + 2>/dev/null | head -1)
    if [[ -z "$AWS_JSON" ]]; then
        log_error "No AWS resources JSON file found"
        log_info "Please run: ./discover-aws-resources.sh"
        exit 1
    fi
    log_info "Found AWS resources: $AWS_JSON"
fi

if [[ -z "$TF_JSON" ]]; then
    log_info "Auto-detecting Terraform resources file..."
    TF_JSON=$(find . -name "terraform-resources-*.json" -type f -exec ls -t {} + 2>/dev/null | head -1)
    if [[ -z "$TF_JSON" ]]; then
        log_error "No Terraform resources JSON file found"
        log_info "Please run: ./analyze-terraform-state.sh"
        exit 1
    fi
    log_info "Found Terraform resources: $TF_JSON"
fi

# Validate files exist and are readable
for file in "$AWS_JSON" "$TF_JSON"; do
    if [[ ! -f "$file" ]]; then
        log_error "File not found: $file"
        exit 1
    fi
    if [[ ! -r "$file" ]]; then
        log_error "File not readable: $file"
        exit 1
    fi
done

# Validate JSON files
log_debug "Validating JSON files..."
if ! jq empty "$AWS_JSON" 2>/dev/null; then
    log_error "Invalid JSON in AWS file: $AWS_JSON"
    exit 1
fi

if ! jq empty "$TF_JSON" 2>/dev/null; then
    log_error "Invalid JSON in Terraform file: $TF_JSON"
    exit 1
fi

log_info "Using files:"
log_info "  AWS: $AWS_JSON"
log_info "  Terraform: $TF_JSON"

OUTPUT_FILE="unmanaged-resources-$(date +%Y%m%d-%H%M%S).txt"

echo "Resource Comparison Report" | tee $OUTPUT_FILE
echo "==========================" | tee -a $OUTPUT_FILE
echo "Date: $(date)" | tee -a $OUTPUT_FILE
echo "AWS Resources File: $AWS_JSON" | tee -a $OUTPUT_FILE
echo "Terraform State File: $TF_JSON" | tee -a $OUTPUT_FILE
echo "" | tee -a $OUTPUT_FILE

# Function to print section
print_section() {
    echo "" | tee -a $OUTPUT_FILE
    echo "==================================================================" | tee -a $OUTPUT_FILE
    echo "$1" | tee -a $OUTPUT_FILE
    echo "==================================================================" | tee -a $OUTPUT_FILE
}

# Focus on identification only - no import script generation

# Function to compare resource arrays
compare_resources() {
    local resource_type=$1
    local aws_field=$2
    local tf_field=$3
    local display_name=$4

    echo "" | tee -a $OUTPUT_FILE
    echo "$display_name:" | tee -a $OUTPUT_FILE

    # Create temp files for comparison
    local aws_temp="/tmp/aws_${resource_type}.txt"
    local tf_temp="/tmp/tf_${resource_type}.txt"

    # Get arrays from JSON files and sort them
    jq -r ".${aws_field}[]?" "$AWS_JSON" 2>/dev/null | sort | uniq > "$aws_temp"
    jq -r ".${tf_field}[]?" "$TF_JSON" 2>/dev/null | sort | uniq > "$tf_temp"

    # Find resources in AWS but not in Terraform
    UNMANAGED=$(comm -23 "$aws_temp" "$tf_temp" 2>/dev/null)

    if [ -n "$UNMANAGED" ]; then
        echo "  ⚠️  Unmanaged resources found:" | tee -a $OUTPUT_FILE
        echo "$UNMANAGED" | while read resource; do
            if [ -n "$resource" ] && [ "$resource" != "null" ]; then
                echo "    - $resource" | tee -a $OUTPUT_FILE
            fi
        done
    else
        echo "  ✅ All resources are managed by Terraform" | tee -a $OUTPUT_FILE
    fi

    # Count comparison
    AWS_COUNT=$(cat "$aws_temp" | grep -v "^$" | wc -l | tr -d ' ')
    TF_COUNT=$(cat "$tf_temp" | grep -v "^$" | wc -l | tr -d ' ')
    UNMANAGED_COUNT=$(echo "$UNMANAGED" | grep -v "^$" | wc -l | tr -d ' ')
    [ -z "$UNMANAGED" ] && UNMANAGED_COUNT=0

    echo "  Summary: AWS=$AWS_COUNT, Terraform=$TF_COUNT, Unmanaged=$UNMANAGED_COUNT" | tee -a $OUTPUT_FILE

    # Clean up temp files
    rm -f "$aws_temp" "$tf_temp"
}

# Compare each resource type
print_section "RESOURCE COMPARISON"

compare_resources "security_group" "security_groups" "security_groups" "Security Groups"
compare_resources "vpc" "vpcs" "vpcs" "VPCs"
compare_resources "subnet" "subnets" "subnets" "Subnets"
compare_resources "rds_instance" "rds_instances" "rds_instances" "RDS Instances"
compare_resources "rds_cluster" "rds_clusters" "rds_clusters" "RDS Clusters"
compare_resources "elasticache_cluster" "elasticache_clusters" "elasticache_clusters" "ElastiCache Clusters"
compare_resources "s3_bucket" "s3_buckets" "s3_buckets" "S3 Buckets"
compare_resources "load_balancer" "load_balancers" "load_balancers" "Load Balancers"
compare_resources "ecs_cluster" "ecs_clusters" "ecs_clusters" "ECS Clusters"
compare_resources "ecs_service" "ecs_services" "ecs_services" "ECS Services"
compare_resources "iam_role" "iam_roles" "iam_roles" "IAM Roles"
compare_resources "log_group" "log_groups" "log_groups" "CloudWatch Log Groups"

# Overall summary
print_section "OVERALL SUMMARY"

# Count unmanaged resources from the output
TOTAL_UNMANAGED=0
RESOURCE_TYPES=("security_group" "vpc" "subnet" "rds_instance" "rds_cluster" "elasticache_cluster" "s3_bucket" "load_balancer" "ecs_cluster" "ecs_service" "iam_role" "log_group")

for resource_type in "${RESOURCE_TYPES[@]}"; do
    aws_field="${resource_type}s"
    tf_field="${resource_type}s"

    # Handle pluralization exceptions
    case "$resource_type" in
        "security_group") aws_field="security_groups"; tf_field="security_groups" ;;
        "elasticache_cluster") aws_field="elasticache_clusters"; tf_field="elasticache_clusters" ;;
        "load_balancer") aws_field="load_balancers"; tf_field="load_balancers" ;;
        "ecs_cluster") aws_field="ecs_clusters"; tf_field="ecs_clusters" ;;
        "ecs_service") aws_field="ecs_services"; tf_field="ecs_services" ;;
        "iam_role") aws_field="iam_roles"; tf_field="iam_roles" ;;
        "log_group") aws_field="log_groups"; tf_field="log_groups" ;;
    esac

    aws_temp="/tmp/count_aws_${resource_type}.txt"
    tf_temp="/tmp/count_tf_${resource_type}.txt"

    jq -r ".${aws_field}[]?" "$AWS_JSON" 2>/dev/null | sort | uniq > "$aws_temp"
    jq -r ".${tf_field}[]?" "$TF_JSON" 2>/dev/null | sort | uniq > "$tf_temp"

    UNMANAGED_COUNT=$(comm -23 "$aws_temp" "$tf_temp" 2>/dev/null | grep -v "^$" | wc -l | tr -d ' ')
    TOTAL_UNMANAGED=$((TOTAL_UNMANAGED + UNMANAGED_COUNT))

    rm -f "$aws_temp" "$tf_temp"
done

echo "Total unmanaged resources found: $TOTAL_UNMANAGED" | tee -a $OUTPUT_FILE
echo "" | tee -a $OUTPUT_FILE

if [ "$TOTAL_UNMANAGED" -gt 0 ]; then
    echo "⚠️  Action Required:" | tee -a $OUTPUT_FILE
    echo "  1. Review the unmanaged resources listed above" | tee -a $OUTPUT_FILE
    echo "  2. Create import blocks in your Terraform code" | tee -a $OUTPUT_FILE
    echo "  3. Run 'tofu plan' to verify import configuration" | tee -a $OUTPUT_FILE
    echo "  4. Apply via GitHub Actions to import resources" | tee -a $OUTPUT_FILE
else
    echo "✅ Excellent! All AWS resources are managed by Terraform." | tee -a $OUTPUT_FILE
    echo "No import actions needed." | tee -a $OUTPUT_FILE
fi

# Check for orphaned state (resources in Terraform but not in AWS)
print_section "ORPHANED STATE CHECK"

echo "Checking for resources in Terraform state but not in AWS..." | tee -a $OUTPUT_FILE
echo "(These might be deleted resources still in state)" | tee -a $OUTPUT_FILE

check_orphaned() {
    local resource_type=$1
    local aws_field=$2
    local tf_field=$3
    local display_name=$4

    echo "" | tee -a $OUTPUT_FILE
    echo "$display_name:" | tee -a $OUTPUT_FILE

    # Create temp files
    local aws_temp="/tmp/aws_orphan_${resource_type}.txt"
    local tf_temp="/tmp/tf_orphan_${resource_type}.txt"

    jq -r ".${aws_field}[]?" "$AWS_JSON" 2>/dev/null | sort | uniq > "$aws_temp"
    jq -r ".${tf_field}[]?" "$TF_JSON" 2>/dev/null | sort | uniq > "$tf_temp"

    ORPHANED=$(comm -13 "$aws_temp" "$tf_temp" 2>/dev/null)

    if [ -n "$ORPHANED" ]; then
        echo "  ⚠️  Orphaned state entries found:" | tee -a $OUTPUT_FILE
        echo "$ORPHANED" | while read resource; do
            if [ -n "$resource" ] && [ "$resource" != "null" ]; then
                echo "    - $resource (in Terraform but not in AWS)" | tee -a $OUTPUT_FILE
            fi
        done
    else
        echo "  ✅ No orphaned state entries" | tee -a $OUTPUT_FILE
    fi

    rm -f "$aws_temp" "$tf_temp"
}

check_orphaned "security_group" "security_groups" "security_groups" "Security Groups"
check_orphaned "rds_instance" "rds_instances" "rds_instances" "RDS Instances"
check_orphaned "s3_bucket" "s3_buckets" "s3_buckets" "S3 Buckets"
check_orphaned "ecs_cluster" "ecs_clusters" "ecs_clusters" "ECS Clusters"

echo "" | tee -a $OUTPUT_FILE
echo "===================================================================" | tee -a $OUTPUT_FILE
echo "COMPARISON COMPLETE" | tee -a $OUTPUT_FILE
echo "===================================================================" | tee -a $OUTPUT_FILE
echo "Results saved to: $OUTPUT_FILE" | tee -a $OUTPUT_FILE
echo "" | tee -a $OUTPUT_FILE
echo "Next steps:" | tee -a $OUTPUT_FILE
echo "1. Review unmanaged resources listed above" | tee -a $OUTPUT_FILE
echo "2. Check for any orphaned state entries" | tee -a $OUTPUT_FILE
echo "3. Create import blocks for unmanaged resources" | tee -a $OUTPUT_FILE
echo "4. Apply changes via GitHub Actions workflow" | tee -a $OUTPUT_FILE