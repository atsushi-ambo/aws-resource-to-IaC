#!/bin/bash

# Terraform State Analysis Script
# This script analyzes Terraform state files to identify managed resources

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
Usage: $SCRIPT_NAME [OPTIONS] [STATE_FILE]

Analyze Terraform state files to extract managed resources.

Arguments:
    STATE_FILE      Path to Terraform state file (processes all *.json if not specified)

Options:
    -h, --help      Show this help message
    -v, --verbose   Enable verbose logging
    --no-color      Disable colored output

Examples:
    $SCRIPT_NAME                        # Process all *.json files in directory
    $SCRIPT_NAME prod.tfstate.json      # Process specific state file
    $SCRIPT_NAME -v                     # Verbose processing

Output:
    terraform-resources-YYYYMMDD-HHMMSS.txt     # Human-readable report
    terraform-resources-YYYYMMDD-HHMMSS.json    # Machine-readable data

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
STATE_FILE="${1:-}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_FILE="terraform-resources-${TIMESTAMP}.txt"
JSON_FILE="terraform-resources-${TIMESTAMP}.json"

# If no file specified, process all state files in current directory
if [ -z "$STATE_FILE" ]; then
    echo "Looking for state files in current directory..."
    STATE_FILES=$(ls *.json 2>/dev/null | grep -v "aws-resources-" | grep -v "terraform-resources-" | grep -v "unmanaged-" || true)

    if [ -z "$STATE_FILES" ]; then
        echo "Error: No state files found in current directory"
        echo "Usage: $0 [path/to/state.json]"
        echo "Or place state files in current directory"
        exit 1
    fi

    echo "Found state files:"
    echo "$STATE_FILES"
    echo ""
    echo "Processing all state files to create consolidated report..."
    PROCESS_MULTIPLE=true
else
    PROCESS_MULTIPLE=false
    STATE_FILES="$STATE_FILE"
fi

echo "Terraform State Analysis Report" | tee $OUTPUT_FILE
echo "===============================" | tee -a $OUTPUT_FILE
echo "Date: $(date)" | tee -a $OUTPUT_FILE
if [ "$PROCESS_MULTIPLE" = true ]; then
    echo "Processing multiple state files:" | tee -a $OUTPUT_FILE
    echo "$STATE_FILES" | tee -a $OUTPUT_FILE
else
    echo "State File: $STATE_FILE" | tee -a $OUTPUT_FILE
fi
echo "" | tee -a $OUTPUT_FILE

# Function to print section
print_section() {
    echo "" | tee -a $OUTPUT_FILE
    echo "==================================================================" | tee -a $OUTPUT_FILE
    echo "$1" | tee -a $OUTPUT_FILE
    echo "==================================================================" | tee -a $OUTPUT_FILE
}

# Initialize consolidated arrays
ALL_SECURITY_GROUPS="[]"
ALL_VPCS="[]"
ALL_SUBNETS="[]"
ALL_RDS_INSTANCES="[]"
ALL_RDS_CLUSTERS="[]"
ALL_ELASTICACHE="[]"
ALL_LOAD_BALANCERS="[]"
ALL_S3_BUCKETS="[]"
ALL_CLOUDFRONT="[]"
ALL_ECS_CLUSTERS="[]"
ALL_ECS_SERVICES="[]"
ALL_LOG_GROUPS="[]"
ALL_IAM_ROLES="[]"
ALL_ACM_CERTS="[]"
TOTAL_RESOURCES=0

# Process each state file
for state_file in $STATE_FILES; do
    if [ ! -f "$state_file" ]; then
        echo "Warning: File not found: $state_file" | tee -a $OUTPUT_FILE
        continue
    fi

    # Validate JSON
    if ! jq empty "$state_file" 2>/dev/null; then
        echo "Warning: Invalid JSON in state file: $state_file" | tee -a $OUTPUT_FILE
        continue
    fi

    echo "Processing: $state_file" | tee -a $OUTPUT_FILE

    # Get resource count for this file
    FILE_TOTAL=$(jq '[.resources[]? | select(.mode=="managed") | .instances[]] | length' "$state_file" 2>/dev/null || echo "0")
    TOTAL_RESOURCES=$((TOTAL_RESOURCES + FILE_TOTAL))
    echo "  Resources in this file: $FILE_TOTAL" | tee -a $OUTPUT_FILE

    # Extract and merge resource IDs from this file
    SECURITY_GROUPS=$(jq -r '[.resources[]? | select(.type == "aws_security_group" and .mode == "managed") | .instances[].attributes.id] | unique' "$state_file" 2>/dev/null || echo "[]")
    ALL_SECURITY_GROUPS=$(echo "$ALL_SECURITY_GROUPS $SECURITY_GROUPS" | jq -s 'add | unique')

    VPCS=$(jq -r '[.resources[]? | select(.type == "aws_vpc" and .mode == "managed") | .instances[].attributes.id] | unique' "$state_file" 2>/dev/null || echo "[]")
    ALL_VPCS=$(echo "$ALL_VPCS $VPCS" | jq -s 'add | unique')

    SUBNETS=$(jq -r '[.resources[]? | select(.type == "aws_subnet" and .mode == "managed") | .instances[].attributes.id] | unique' "$state_file" 2>/dev/null || echo "[]")
    ALL_SUBNETS=$(echo "$ALL_SUBNETS $SUBNETS" | jq -s 'add | unique')

    RDS_INSTANCES=$(jq -r '[.resources[]? | select(.type == "aws_db_instance" and .mode == "managed") | .instances[].attributes.id // .instances[].attributes.identifier] | unique' "$state_file" 2>/dev/null || echo "[]")
    ALL_RDS_INSTANCES=$(echo "$ALL_RDS_INSTANCES $RDS_INSTANCES" | jq -s 'add | unique')

    RDS_CLUSTERS=$(jq -r '[.resources[]? | select(.type == "aws_rds_cluster" and .mode == "managed") | .instances[].attributes.cluster_identifier // .instances[].attributes.id] | unique' "$state_file" 2>/dev/null || echo "[]")
    ALL_RDS_CLUSTERS=$(echo "$ALL_RDS_CLUSTERS $RDS_CLUSTERS" | jq -s 'add | unique')

    ELASTICACHE=$(jq -r '[.resources[]? | select((.type == "aws_elasticache_cluster" or .type == "aws_elasticache_replication_group") and .mode == "managed") | .instances[].attributes.id // .instances[].attributes.replication_group_id] | unique' "$state_file" 2>/dev/null || echo "[]")
    ALL_ELASTICACHE=$(echo "$ALL_ELASTICACHE $ELASTICACHE" | jq -s 'add | unique')

    LOAD_BALANCERS=$(jq -r '[.resources[]? | select((.type == "aws_lb" or .type == "aws_alb" or .type == "aws_elb") and .mode == "managed") | .instances[].attributes.name // .instances[].attributes.id] | unique' "$state_file" 2>/dev/null || echo "[]")
    ALL_LOAD_BALANCERS=$(echo "$ALL_LOAD_BALANCERS $LOAD_BALANCERS" | jq -s 'add | unique')

    S3_BUCKETS=$(jq -r '[.resources[]? | select(.type == "aws_s3_bucket" and .mode == "managed") | .instances[].attributes.id // .instances[].attributes.bucket] | unique' "$state_file" 2>/dev/null || echo "[]")
    ALL_S3_BUCKETS=$(echo "$ALL_S3_BUCKETS $S3_BUCKETS" | jq -s 'add | unique')

    CLOUDFRONT=$(jq -r '[.resources[]? | select(.type == "aws_cloudfront_distribution" and .mode == "managed") | .instances[].attributes.id] | unique' "$state_file" 2>/dev/null || echo "[]")
    ALL_CLOUDFRONT=$(echo "$ALL_CLOUDFRONT $CLOUDFRONT" | jq -s 'add | unique')

    ECS_CLUSTERS=$(jq -r '[.resources[]? | select(.type == "aws_ecs_cluster" and .mode == "managed") | .instances[].attributes.name] | unique' "$state_file" 2>/dev/null || echo "[]")
    ALL_ECS_CLUSTERS=$(echo "$ALL_ECS_CLUSTERS $ECS_CLUSTERS" | jq -s 'add | unique')

    ECS_SERVICES=$(jq -r '[.resources[]? | select(.type == "aws_ecs_service" and .mode == "managed") | .instances[] | "\(.attributes.cluster | split("/")[-1] // .attributes.cluster):\(.attributes.name)"] | unique' "$state_file" 2>/dev/null || echo "[]")
    ALL_ECS_SERVICES=$(echo "$ALL_ECS_SERVICES $ECS_SERVICES" | jq -s 'add | unique')

    LOG_GROUPS=$(jq -r '[.resources[]? | select(.type == "aws_cloudwatch_log_group" and .mode == "managed") | .instances[].attributes.name // .instances[].attributes.id] | unique' "$state_file" 2>/dev/null || echo "[]")
    ALL_LOG_GROUPS=$(echo "$ALL_LOG_GROUPS $LOG_GROUPS" | jq -s 'add | unique')

    IAM_ROLES=$(jq -r '[.resources[]? | select(.type == "aws_iam_role" and .mode == "managed") | .instances[].attributes.name] | unique' "$state_file" 2>/dev/null || echo "[]")
    ALL_IAM_ROLES=$(echo "$ALL_IAM_ROLES $IAM_ROLES" | jq -s 'add | unique')

    ACM_CERTS=$(jq -r '[.resources[]? | select(.type == "aws_acm_certificate" and .mode == "managed") | .instances[].attributes.arn] | unique' "$state_file" 2>/dev/null || echo "[]")
    ALL_ACM_CERTS=$(echo "$ALL_ACM_CERTS $ACM_CERTS" | jq -s 'add | unique')
done

# Generate consolidated summary
print_section "CONSOLIDATED RESOURCE SUMMARY"
echo "Total Managed Resources Across All States: $TOTAL_RESOURCES" | tee -a $OUTPUT_FILE
echo "" | tee -a $OUTPUT_FILE

# Generate consolidated resource type summary
echo "Consolidated Resources by Type:" | tee -a $OUTPUT_FILE
for state_file in $STATE_FILES; do
    if [ -f "$state_file" ] && jq empty "$state_file" 2>/dev/null; then
        jq -r '.resources[]? | select(.mode=="managed") | .type' "$state_file" 2>/dev/null
    fi
done | sort | uniq -c | sort -rn | tee -a $OUTPUT_FILE

# Display consolidated resources by category
print_section "CONSOLIDATED EC2 RESOURCES"

echo "Security Groups ($(echo $ALL_SECURITY_GROUPS | jq 'length')):" | tee -a $OUTPUT_FILE
echo "$ALL_SECURITY_GROUPS" | jq -r '.[]' 2>/dev/null | while read sg; do
    [ -n "$sg" ] && echo "  - $sg" | tee -a $OUTPUT_FILE
done

echo "" | tee -a $OUTPUT_FILE
echo "VPCs ($(echo $ALL_VPCS | jq 'length')):" | tee -a $OUTPUT_FILE
echo "$ALL_VPCS" | jq -r '.[]' 2>/dev/null | while read vpc; do
    [ -n "$vpc" ] && echo "  - $vpc" | tee -a $OUTPUT_FILE
done

echo "" | tee -a $OUTPUT_FILE
echo "Subnets ($(echo $ALL_SUBNETS | jq 'length')):" | tee -a $OUTPUT_FILE
echo "$ALL_SUBNETS" | jq -r '.[]' 2>/dev/null | while read subnet; do
    [ -n "$subnet" ] && echo "  - $subnet" | tee -a $OUTPUT_FILE
done

print_section "CONSOLIDATED RDS RESOURCES"

echo "RDS Instances ($(echo $ALL_RDS_INSTANCES | jq 'length')):" | tee -a $OUTPUT_FILE
echo "$ALL_RDS_INSTANCES" | jq -r '.[]' 2>/dev/null | while read rds; do
    [ -n "$rds" ] && echo "  - $rds" | tee -a $OUTPUT_FILE
done

echo "" | tee -a $OUTPUT_FILE
echo "RDS Clusters ($(echo $ALL_RDS_CLUSTERS | jq 'length')):" | tee -a $OUTPUT_FILE
echo "$ALL_RDS_CLUSTERS" | jq -r '.[]' 2>/dev/null | while read cluster; do
    [ -n "$cluster" ] && echo "  - $cluster" | tee -a $OUTPUT_FILE
done

print_section "CONSOLIDATED OTHER KEY RESOURCES"

echo "S3 Buckets ($(echo $ALL_S3_BUCKETS | jq 'length')):" | tee -a $OUTPUT_FILE
echo "$ALL_S3_BUCKETS" | jq -r '.[]' 2>/dev/null | while read bucket; do
    [ -n "$bucket" ] && echo "  - $bucket" | tee -a $OUTPUT_FILE
done

echo "" | tee -a $OUTPUT_FILE
echo "Load Balancers ($(echo $ALL_LOAD_BALANCERS | jq 'length')):" | tee -a $OUTPUT_FILE
echo "$ALL_LOAD_BALANCERS" | jq -r '.[]' 2>/dev/null | while read lb; do
    [ -n "$lb" ] && echo "  - $lb" | tee -a $OUTPUT_FILE
done

echo "" | tee -a $OUTPUT_FILE
echo "ECS Clusters ($(echo $ALL_ECS_CLUSTERS | jq 'length')):" | tee -a $OUTPUT_FILE
echo "$ALL_ECS_CLUSTERS" | jq -r '.[]' 2>/dev/null | while read cluster; do
    [ -n "$cluster" ] && echo "  - $cluster" | tee -a $OUTPUT_FILE
done

echo "" | tee -a $OUTPUT_FILE
echo "IAM Roles ($(echo $ALL_IAM_ROLES | jq 'length')):" | tee -a $OUTPUT_FILE
echo "$ALL_IAM_ROLES" | jq -r '.[]' 2>/dev/null | while read role; do
    [ -n "$role" ] && echo "  - $role" | tee -a $OUTPUT_FILE
done

# Generate consolidated JSON output for comparison
print_section "GENERATING CONSOLIDATED JSON OUTPUT"

cat > "$JSON_FILE" <<EOF
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "state_files": [$(echo "$STATE_FILES" | sed 's/^/"/' | sed 's/$/"/' | tr '\n' ',' | sed 's/,$//')],
  "total_resources": $TOTAL_RESOURCES,
  "security_groups": $ALL_SECURITY_GROUPS,
  "vpcs": $ALL_VPCS,
  "subnets": $ALL_SUBNETS,
  "rds_instances": $ALL_RDS_INSTANCES,
  "rds_clusters": $ALL_RDS_CLUSTERS,
  "elasticache_clusters": $ALL_ELASTICACHE,
  "load_balancers": $ALL_LOAD_BALANCERS,
  "s3_buckets": $ALL_S3_BUCKETS,
  "cloudfront_distributions": $ALL_CLOUDFRONT,
  "ecs_clusters": $ALL_ECS_CLUSTERS,
  "ecs_services": $ALL_ECS_SERVICES,
  "log_groups": $ALL_LOG_GROUPS,
  "iam_roles": $ALL_IAM_ROLES,
  "acm_certificates": $ALL_ACM_CERTS
}
EOF

echo "Consolidated analysis complete!" | tee -a $OUTPUT_FILE
echo "" | tee -a $OUTPUT_FILE
echo "===================================================================" | tee -a $OUTPUT_FILE
echo "RESULTS" | tee -a $OUTPUT_FILE
echo "===================================================================" | tee -a $OUTPUT_FILE
echo "Output files created:" | tee -a $OUTPUT_FILE
echo "  - Human-readable report: $OUTPUT_FILE" | tee -a $OUTPUT_FILE
echo "  - JSON for comparison: $JSON_FILE" | tee -a $OUTPUT_FILE
echo "" | tee -a $OUTPUT_FILE
echo "Next steps:" | tee -a $OUTPUT_FILE
echo "1. Run discover-aws-resources.sh to scan actual AWS resources" | tee -a $OUTPUT_FILE
echo "2. Run compare-resources.sh to find unmanaged resources" | tee -a $OUTPUT_FILE