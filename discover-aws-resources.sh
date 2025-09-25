#!/bin/bash

# AWS Resource Discovery Script
# This script lists all AWS resources to help identify what needs to be imported into Terraform

set -euo pipefail

# Configuration
SCRIPT_NAME="$(basename "$0")"
LOG_LEVEL="INFO"  # DEBUG, INFO, WARN, ERROR

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
Usage: $SCRIPT_NAME [OPTIONS] [PROFILE] [REGION]

Discover AWS resources and generate reports for Terraform import planning.

Arguments:
    PROFILE         AWS profile to use (default: default)
    REGION          AWS region to scan (default: profile's default region or us-east-1)

Options:
    -h, --help      Show this help message
    -v, --verbose   Enable verbose logging
    -d, --debug     Enable debug logging
    --no-color      Disable colored output

Examples:
    $SCRIPT_NAME                           # Use default profile and region
    $SCRIPT_NAME production                # Use production profile
    $SCRIPT_NAME staging us-west-2         # Use staging profile in us-west-2
    $SCRIPT_NAME -v production us-east-1   # Verbose output

Output files:
    aws-resources-YYYYMMDD-HHMMSS.txt     # Human-readable report
    aws-resources-YYYYMMDD-HHMMSS.json    # Machine-readable data

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
        -d|--debug)
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

# Dependency checks
check_dependencies() {
    local missing_deps=()

    command -v aws >/dev/null 2>&1 || missing_deps+=("aws-cli")
    command -v jq >/dev/null 2>&1 || missing_deps+=("jq")

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        echo "Please install missing dependencies:"
        [[ " ${missing_deps[*]} " =~ " aws-cli " ]] && echo "  - AWS CLI: https://aws.amazon.com/cli/"
        [[ " ${missing_deps[*]} " =~ " jq " ]] && echo "  - jq: brew install jq (macOS) or apt install jq (Ubuntu)"
        exit 1
    fi
    log_debug "All dependencies satisfied"
}

# Read-only wrapper for AWS CLI with error handling
aws_safe() {
    # Block any write operations
    if echo "$*" | grep -qE "(create|delete|update|modify|put|terminate|stop|start|attach|detach)"; then
        log_error "Write operation blocked for safety: $*"
        return 1
    fi

    log_debug "Executing: aws $*"
    if ! aws "$@" 2>/dev/null; then
        log_warn "AWS command failed: aws $*"
        return 1
    fi
}

# Progress indicator
show_progress() {
    local current=$1
    local total=$2
    local task=$3
    local percent=$((current * 100 / total))
    printf "\r${GREEN}[%3d%%]${NC} %s" "$percent" "$task"
    [[ $current -eq $total ]] && echo
}

check_dependencies

# Parse remaining arguments
PROFILE="${1:-default}"
REGION="${2:-}"

# Validate AWS profile
if ! aws configure list-profiles 2>/dev/null | grep -q "^${PROFILE}$"; then
    if [[ "$PROFILE" != "default" ]]; then
        log_error "AWS profile '$PROFILE' not found"
        log_info "Available profiles: $(aws configure list-profiles 2>/dev/null | tr '\n' ' ' || echo 'none')"
        exit 1
    fi
fi

# Set region
if [[ -z "$REGION" ]]; then
    REGION=$(aws configure get region --profile "$PROFILE" 2>/dev/null || echo 'us-east-1')
fi

log_info "Using profile: $PROFILE, region: $REGION"

# Validate AWS credentials
if ! aws sts get-caller-identity --profile "$PROFILE" >/dev/null 2>&1; then
    log_error "AWS credentials not valid for profile '$PROFILE'"
    log_info "Please run: aws configure --profile $PROFILE"
    exit 1
fi

# Set up output files
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_FILE="aws-resources-${TIMESTAMP}.txt"
JSON_FILE="aws-resources-${TIMESTAMP}.json"

# Export profile for all AWS commands
export AWS_PROFILE="$PROFILE"

# Initialize report files
log_info "Starting AWS resource discovery..."
log_debug "Output files: $OUTPUT_FILE, $JSON_FILE"

# Get account info
ACCOUNT_ID=$(aws_safe sts get-caller-identity --query Account --output text)
ACCOUNT_ALIAS=$(aws_safe iam list-account-aliases --query 'AccountAliases[0]' --output text 2>/dev/null || echo "N/A")

# Create report header
{
    echo "AWS Resource Discovery Report"
    echo "============================"
    echo "Profile: $PROFILE"
    echo "Region: $REGION"
    echo "Account ID: $ACCOUNT_ID"
    echo "Account Alias: $ACCOUNT_ALIAS"
    echo "Date: $(date)"
    echo "Script: $SCRIPT_NAME"
    echo ""
} | tee "$OUTPUT_FILE"

# Enhanced section printing with progress
CURRENT_SECTION=0
TOTAL_SECTIONS=20  # Update this as sections are added

print_section() {
    local section_name="$1"
    CURRENT_SECTION=$((CURRENT_SECTION + 1))

    show_progress "$CURRENT_SECTION" "$TOTAL_SECTIONS" "Processing $section_name..."

    {
        echo ""
        echo "=================================================================="
        echo "$section_name"
        echo "=================================================================="
    } | tee -a "$OUTPUT_FILE"

    log_debug "Processing section: $section_name"
}

# Safe AWS query with error handling
aws_query() {
    local service="$1"
    local command="$2"
    shift 2

    log_debug "Querying $service: $command"

    if aws_safe "$service" "$command" --region "$REGION" "$@" --output table 2>/dev/null; then
        return 0
    else
        echo "Error: Unable to query $service $command" | tee -a "$OUTPUT_FILE"
        log_warn "Failed to query $service $command"
        return 1
    fi
}

# EC2 Resources
print_section "EC2 INSTANCES"
aws_query ec2 describe-instances \
    --query "Reservations[*].Instances[*].[InstanceId,Tags[?Key=='Name']|[0].Value,State.Name,InstanceType,PrivateIpAddress,PublicIpAddress]" | tee -a "$OUTPUT_FILE"

print_section "SECURITY GROUPS"
aws_query ec2 describe-security-groups \
    --query "SecurityGroups[*].[GroupId,GroupName,VpcId,Description]" | tee -a "$OUTPUT_FILE"

print_section "VPCs"
aws_query ec2 describe-vpcs \
    --query "Vpcs[*].[VpcId,Tags[?Key=='Name']|[0].Value,CidrBlock,State]" | tee -a "$OUTPUT_FILE"

print_section "SUBNETS"
aws_query ec2 describe-subnets \
    --query "Subnets[*].[SubnetId,Tags[?Key=='Name']|[0].Value,CidrBlock,VpcId,AvailabilityZone]" | tee -a "$OUTPUT_FILE"

print_section "ROUTE TABLES"
aws_query ec2 describe-route-tables \
    --query "RouteTables[*].[RouteTableId,Tags[?Key=='Name']|[0].Value,VpcId]" | tee -a "$OUTPUT_FILE"

print_section "INTERNET GATEWAYS"
aws_query ec2 describe-internet-gateways \
    --query "InternetGateways[*].[InternetGatewayId,Tags[?Key=='Name']|[0].Value,Attachments[0].VpcId]" | tee -a "$OUTPUT_FILE"

print_section "NAT GATEWAYS"
aws_query ec2 describe-nat-gateways \
    --query "NatGateways[*].[NatGatewayId,State,SubnetId,Tags[?Key=='Name']|[0].Value]" | tee -a "$OUTPUT_FILE"

print_section "ELASTIC IPs"
aws_query ec2 describe-addresses \
    --query "Addresses[*].[AllocationId,PublicIp,InstanceId,AssociationId,Tags[?Key=='Name']|[0].Value]" | tee -a "$OUTPUT_FILE"

print_section "VPC ENDPOINTS"
aws_query ec2 describe-vpc-endpoints \
    --query "VpcEndpoints[*].[VpcEndpointId,ServiceName,VpcId,State]" | tee -a "$OUTPUT_FILE"

# RDS Resources
print_section "RDS INSTANCES"
aws_query rds describe-db-instances \
    --query "DBInstances[*].[DBInstanceIdentifier,Engine,DBInstanceStatus,DBInstanceClass,AllocatedStorage,MultiAZ]" | tee -a "$OUTPUT_FILE"

print_section "RDS CLUSTERS"
aws_query rds describe-db-clusters \
    --query "DBClusters[*].[DBClusterIdentifier,Engine,Status,MasterUsername,DatabaseName]" | tee -a "$OUTPUT_FILE"

print_section "RDS SUBNET GROUPS"
aws_query rds describe-db-subnet-groups \
    --query "DBSubnetGroups[*].[DBSubnetGroupName,VpcId,SubnetGroupStatus]" | tee -a "$OUTPUT_FILE"

print_section "RDS PARAMETER GROUPS"
aws_query rds describe-db-parameter-groups \
    --query "DBParameterGroups[?!starts_with(DBParameterGroupName, 'default.')].{Name:DBParameterGroupName,Family:DBParameterGroupFamily,Description:Description}" | tee -a "$OUTPUT_FILE"

# ElastiCache Resources
print_section "ELASTICACHE CLUSTERS"
aws_query elasticache describe-cache-clusters \
    --query "CacheClusters[*].[CacheClusterId,Engine,CacheClusterStatus,CacheNodeType,NumCacheNodes]" | tee -a "$OUTPUT_FILE"

print_section "ELASTICACHE REPLICATION GROUPS"
aws_query elasticache describe-replication-groups \
    --query "ReplicationGroups[*].[ReplicationGroupId,Status,CacheNodeType,AutomaticFailover]" | tee -a "$OUTPUT_FILE"

print_section "ELASTICACHE SUBNET GROUPS"
aws_query elasticache describe-cache-subnet-groups \
    --query "CacheSubnetGroups[*].[CacheSubnetGroupName,VpcId]" | tee -a "$OUTPUT_FILE"

# Load Balancers
print_section "APPLICATION/NETWORK LOAD BALANCERS (v2)"
aws elbv2 describe-load-balancers --region $REGION \
    --query "LoadBalancers[*].[LoadBalancerName,DNSName,Type,Scheme,State.Code,VpcId]" \
    --output table | tee -a $OUTPUT_FILE

print_section "TARGET GROUPS"
aws elbv2 describe-target-groups --region $REGION \
    --query "TargetGroups[*].[TargetGroupName,Protocol,Port,VpcId,TargetType]" \
    --output table | tee -a $OUTPUT_FILE

print_section "CLASSIC LOAD BALANCERS"
aws elb describe-load-balancers --region $REGION \
    --query "LoadBalancerDescriptions[*].[LoadBalancerName,DNSName,Scheme,VPCId]" \
    --output table 2>/dev/null | tee -a $OUTPUT_FILE

# S3 Buckets (Global)
print_section "S3 BUCKETS"
aws s3api list-buckets \
    --query "Buckets[*].[Name,CreationDate]" \
    --output table | tee -a $OUTPUT_FILE

# CloudFront (Global)
print_section "CLOUDFRONT DISTRIBUTIONS"
aws cloudfront list-distributions \
    --query "DistributionList.Items[*].[Id,DomainName,Status,PriceClass,Enabled]" \
    --output table 2>/dev/null | tee -a $OUTPUT_FILE

# Route53 (Global)
print_section "ROUTE53 HOSTED ZONES"
aws route53 list-hosted-zones \
    --query "HostedZones[*].[Id,Name,Config.PrivateZone,ResourceRecordSetCount]" \
    --output table | tee -a $OUTPUT_FILE

# ECS Resources
print_section "ECS CLUSTERS"
aws ecs list-clusters --region $REGION --output json | jq -r '.clusterArns[]' 2>/dev/null | while read cluster; do
    if [ ! -z "$cluster" ]; then
        cluster_name=$(echo $cluster | awk -F/ '{print $NF}')
        echo "Cluster: $cluster_name" | tee -a $OUTPUT_FILE
        aws ecs describe-clusters --region $REGION --clusters "$cluster" \
            --query "clusters[*].[clusterName,status,registeredContainerInstancesCount,runningTasksCount]" \
            --output table | tee -a $OUTPUT_FILE
    fi
done

print_section "ECS SERVICES"
aws ecs list-clusters --region $REGION --output json | jq -r '.clusterArns[]' 2>/dev/null | while read cluster; do
    if [ ! -z "$cluster" ]; then
        cluster_name=$(echo $cluster | awk -F/ '{print $NF}')
        echo "Cluster: $cluster_name" | tee -a $OUTPUT_FILE
        aws ecs list-services --region $REGION --cluster "$cluster" --output json | jq -r '.serviceArns[]' 2>/dev/null | while read service; do
            if [ ! -z "$service" ]; then
                aws ecs describe-services --region $REGION --cluster "$cluster" --services "$service" \
                    --query "services[*].[serviceName,status,desiredCount,runningCount,launchType]" \
                    --output table | tee -a $OUTPUT_FILE
            fi
        done
    fi
done

# EFS
print_section "EFS FILE SYSTEMS"
aws efs describe-file-systems --region $REGION \
    --query "FileSystems[*].[FileSystemId,Name,LifeCycleState,NumberOfMountTargets,SizeInBytes.Value]" \
    --output table | tee -a $OUTPUT_FILE

# CloudWatch
print_section "CLOUDWATCH LOG GROUPS"
echo "Total count: $(aws logs describe-log-groups --region $REGION --query 'length(logGroups)' --output text)" | tee -a $OUTPUT_FILE
aws logs describe-log-groups --region $REGION \
    --query "logGroups[*].[logGroupName,retentionInDays,storedBytes]" \
    --output table | tee -a $OUTPUT_FILE

print_section "CLOUDWATCH ALARMS"
aws cloudwatch describe-alarms --region $REGION \
    --query "MetricAlarms[*].[AlarmName,StateValue,MetricName,Namespace]" \
    --output table | head -50 | tee -a $OUTPUT_FILE
echo "... (showing first 50 alarms)" | tee -a $OUTPUT_FILE

# ACM Certificates
print_section "ACM CERTIFICATES"
echo "Certificates in $REGION:" | tee -a $OUTPUT_FILE
aws acm list-certificates --region $REGION \
    --query "CertificateSummaryList[*].[DomainName,CertificateArn,Status]" \
    --output table | tee -a $OUTPUT_FILE

echo "" | tee -a $OUTPUT_FILE
echo "Certificates in us-east-1 (for CloudFront):" | tee -a $OUTPUT_FILE
aws acm list-certificates --region us-east-1 \
    --query "CertificateSummaryList[*].[DomainName,CertificateArn,Status]" \
    --output table | tee -a $OUTPUT_FILE

# IAM (Global) - Custom resources only
print_section "CUSTOM IAM ROLES"
aws iam list-roles \
    --query "Roles[?!starts_with(Path, '/aws-service-role/') && !starts_with(RoleName, 'AWS')].{RoleName:RoleName,Path:Path,CreateDate:CreateDate}" \
    --output table | tee -a $OUTPUT_FILE

print_section "CUSTOM IAM POLICIES"
aws iam list-policies --scope Local \
    --query "Policies[*].[PolicyName,Arn,CreateDate,AttachmentCount]" \
    --output table | tee -a $OUTPUT_FILE

print_section "IAM USERS"
aws iam list-users \
    --query "Users[*].[UserName,CreateDate,PasswordLastUsed]" \
    --output table | tee -a $OUTPUT_FILE

print_section "IAM GROUPS"
aws iam list-groups \
    --query "Groups[*].[GroupName,Path,CreateDate]" \
    --output table | tee -a $OUTPUT_FILE

print_section "IAM INSTANCE PROFILES"
aws iam list-instance-profiles \
    --query "InstanceProfiles[*].[InstanceProfileName,Path,CreateDate]" \
    --output table | tee -a $OUTPUT_FILE

# SNS Topics
print_section "SNS TOPICS"
aws sns list-topics --region $REGION \
    --query "Topics[*].[TopicArn]" \
    --output table | tee -a $OUTPUT_FILE

# SQS Queues
print_section "SQS QUEUES"
aws sqs list-queues --region $REGION \
    --query "QueueUrls[*]" \
    --output table | tee -a $OUTPUT_FILE

# Additional Resources Often Missed
print_section "ECS TASK DEFINITIONS (Latest Only)"
# Get all task definitions, group by family, and show only the latest revision
aws ecs list-task-definitions --region $REGION --status ACTIVE --output json 2>/dev/null | \
    jq -r '.taskDefinitionArns[]' | \
    awk -F: '{family=$1":"$2":"$3":"$4":"$5":"$6; rev=$7}
         {if (!seen[family] || rev > max[family]) {max[family]=rev; latest[family]=$0; seen[family]=1}}
         END {for (f in latest) print latest[f]}' | \
    sort | tee -a $OUTPUT_FILE

print_section "SECRETS MANAGER SECRETS"
aws secretsmanager list-secrets --region $REGION \
    --query "SecretList[*].[Name,ARN,CreatedDate]" \
    --output table | tee -a $OUTPUT_FILE

print_section "PARAMETER STORE PARAMETERS"
aws ssm describe-parameters --region $REGION \
    --query "Parameters[*].[Name,Type,LastModifiedDate]" \
    --output table | tee -a $OUTPUT_FILE

print_section "WAF WEB ACLs"
aws wafv2 list-web-acls --region $REGION --scope REGIONAL \
    --query "WebACLs[*].[Name,Id,ARN]" \
    --output table 2>/dev/null | tee -a $OUTPUT_FILE

print_section "CLOUDWATCH LOG METRIC FILTERS"
aws logs describe-metric-filters --region $REGION \
    --query "metricFilters[*].[filterName,logGroupName,metricTransformations[0].metricName]" \
    --output table | tee -a $OUTPUT_FILE

print_section "VPC FLOW LOGS"
aws ec2 describe-flow-logs --region $REGION \
    --query "FlowLogs[*].[FlowLogId,ResourceId,TrafficType,LogDestinationType]" \
    --output table | tee -a $OUTPUT_FILE

print_section "ELASTICACHE PARAMETER GROUPS"
aws elasticache describe-cache-parameter-groups --region $REGION \
    --query "CacheParameterGroups[?!starts_with(CacheParameterGroupName, 'default.')].{Name:CacheParameterGroupName,Family:CacheParameterGroupFamily}" \
    --output table | tee -a $OUTPUT_FILE

print_section "RDS CLUSTER PARAMETER GROUPS"
aws rds describe-db-cluster-parameter-groups --region $REGION \
    --query "DBClusterParameterGroups[?!starts_with(DBClusterParameterGroupName, 'default.')].{Name:DBClusterParameterGroupName,Family:DBParameterGroupFamily}" \
    --output table | tee -a $OUTPUT_FILE

print_section "SECURITY HUB"
aws securityhub describe-hub --region $REGION 2>/dev/null | tee -a $OUTPUT_FILE

print_section "IAM ACCESS ANALYZER"
aws accessanalyzer list-analyzers --region $REGION \
    --query "analyzers[*].[name,status,type]" \
    --output table 2>/dev/null | tee -a $OUTPUT_FILE

# Generate JSON output for comparison
print_section "GENERATING JSON OUTPUT FOR COMPARISON"

echo "Creating JSON output file..." | tee -a $OUTPUT_FILE

# Create JSON output with all resource IDs for easy comparison
cat > $JSON_FILE <<EOF
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "region": "$REGION",
  "account": "$(aws sts get-caller-identity --query Account --output text)",
  "security_groups": [],
  "vpcs": [],
  "subnets": [],
  "rds_instances": [],
  "rds_clusters": [],
  "elasticache_clusters": [],
  "load_balancers": [],
  "s3_buckets": [],
  "cloudfront_distributions": [],
  "ecs_clusters": [],
  "ecs_services": [],
  "log_groups": [],
  "iam_roles": [],
  "acm_certificates": []
}
EOF

# JSON template is now properly generated with variables

# Populate JSON with actual data
# Security Groups
aws ec2 describe-security-groups --region $REGION --query "SecurityGroups[*].GroupId" --output json > /tmp/sg.json
jq --argjson sg "$(cat /tmp/sg.json)" '.security_groups = $sg' $JSON_FILE > /tmp/temp.json && mv /tmp/temp.json $JSON_FILE

# VPCs
aws ec2 describe-vpcs --region $REGION --query "Vpcs[*].VpcId" --output json > /tmp/vpc.json
jq --argjson vpc "$(cat /tmp/vpc.json)" '.vpcs = $vpc' $JSON_FILE > /tmp/temp.json && mv /tmp/temp.json $JSON_FILE

# Subnets
aws ec2 describe-subnets --region $REGION --query "Subnets[*].SubnetId" --output json > /tmp/subnet.json
jq --argjson subnet "$(cat /tmp/subnet.json)" '.subnets = $subnet' $JSON_FILE > /tmp/temp.json && mv /tmp/temp.json $JSON_FILE

# RDS Instances
aws rds describe-db-instances --region $REGION --query "DBInstances[*].DBInstanceIdentifier" --output json > /tmp/rds.json
jq --argjson rds "$(cat /tmp/rds.json)" '.rds_instances = $rds' $JSON_FILE > /tmp/temp.json && mv /tmp/temp.json $JSON_FILE

# RDS Clusters
aws rds describe-db-clusters --region $REGION --query "DBClusters[*].DBClusterIdentifier" --output json > /tmp/rds_clusters.json
jq --argjson clusters "$(cat /tmp/rds_clusters.json)" '.rds_clusters = $clusters' $JSON_FILE > /tmp/temp.json && mv /tmp/temp.json $JSON_FILE

# ElastiCache Clusters
aws elasticache describe-cache-clusters --region $REGION --query "CacheClusters[*].CacheClusterId" --output json > /tmp/ec.json
jq --argjson ec "$(cat /tmp/ec.json)" '.elasticache_clusters = $ec' $JSON_FILE > /tmp/temp.json && mv /tmp/temp.json $JSON_FILE

# Load Balancers (names only, not ARNs)
aws elbv2 describe-load-balancers --region $REGION --query "LoadBalancers[*].LoadBalancerName" --output json > /tmp/lb.json
jq --argjson lb "$(cat /tmp/lb.json)" '.load_balancers = $lb' $JSON_FILE > /tmp/temp.json && mv /tmp/temp.json $JSON_FILE

# S3 Buckets
aws s3api list-buckets --query "Buckets[*].Name" --output json > /tmp/s3.json
jq --argjson s3 "$(cat /tmp/s3.json)" '.s3_buckets = $s3' $JSON_FILE > /tmp/temp.json && mv /tmp/temp.json $JSON_FILE

# CloudFront Distributions
aws cloudfront list-distributions --query "DistributionList.Items[*].Id" --output json 2>/dev/null > /tmp/cf.json || echo '[]' > /tmp/cf.json
jq --argjson cf "$(cat /tmp/cf.json)" '.cloudfront_distributions = $cf' $JSON_FILE > /tmp/temp.json && mv /tmp/temp.json $JSON_FILE

# ECS Clusters
aws ecs list-clusters --region $REGION --query "clusterArns[*]" --output json | jq '[.[] | split("/")[-1]]' > /tmp/ecs_clusters.json
jq --argjson clusters "$(cat /tmp/ecs_clusters.json)" '.ecs_clusters = $clusters' $JSON_FILE > /tmp/temp.json && mv /tmp/temp.json $JSON_FILE

# ECS Services (format: cluster:service)
echo '[]' > /tmp/ecs_services.json
aws ecs list-clusters --region $REGION --output json | jq -r '.clusterArns[]' | while read cluster_arn; do
    cluster_name=$(echo $cluster_arn | awk -F/ '{print $NF}')
    aws ecs list-services --region $REGION --cluster "$cluster_arn" --output json | jq -r '.serviceArns[]' | while read service_arn; do
        service_name=$(echo $service_arn | awk -F/ '{print $NF}')
        echo "\"${cluster_name}:${service_name}\"" >> /tmp/ecs_services_list.txt
    done
done
if [ -f /tmp/ecs_services_list.txt ]; then
    cat /tmp/ecs_services_list.txt | jq -s '.' > /tmp/ecs_services.json
fi
jq --argjson services "$(cat /tmp/ecs_services.json)" '.ecs_services = $services' $JSON_FILE > /tmp/temp.json && mv /tmp/temp.json $JSON_FILE

# CloudWatch Log Groups
aws logs describe-log-groups --region $REGION --query "logGroups[*].logGroupName" --output json > /tmp/logs.json
jq --argjson logs "$(cat /tmp/logs.json)" '.log_groups = $logs' $JSON_FILE > /tmp/temp.json && mv /tmp/temp.json $JSON_FILE

# IAM Roles (custom only)
aws iam list-roles --query "Roles[?!starts_with(Path, '/aws-service-role/') && !starts_with(RoleName, 'AWS')].RoleName" --output json > /tmp/iam.json
jq --argjson iam "$(cat /tmp/iam.json)" '.iam_roles = $iam' $JSON_FILE > /tmp/temp.json && mv /tmp/temp.json $JSON_FILE

# ACM Certificates (both regions)
# Get certificates from primary region
aws acm list-certificates --region $REGION --query "CertificateSummaryList[*].CertificateArn" --output json > /tmp/acm_primary.json
# Get certificates from us-east-1 (for CloudFront)
aws acm list-certificates --region us-east-1 --query "CertificateSummaryList[*].CertificateArn" --output json > /tmp/acm_useast1.json
# Combine both regions
jq -s 'add' /tmp/acm_primary.json /tmp/acm_useast1.json > /tmp/acm_combined.json
jq --argjson acm "$(cat /tmp/acm_combined.json)" '.acm_certificates = $acm' $JSON_FILE > /tmp/temp.json && mv /tmp/temp.json $JSON_FILE

# Clean up temp files
rm -f /tmp/*.json /tmp/ecs_services_list.txt

# Summary
echo "" | tee -a $OUTPUT_FILE
echo "==================================================================" | tee -a $OUTPUT_FILE
echo "DISCOVERY COMPLETE" | tee -a $OUTPUT_FILE
echo "==================================================================" | tee -a $OUTPUT_FILE
echo "Results saved to:" | tee -a $OUTPUT_FILE
echo "  - Human-readable: $OUTPUT_FILE" | tee -a $OUTPUT_FILE
echo "  - JSON for comparison: $JSON_FILE" | tee -a $OUTPUT_FILE
echo "" | tee -a $OUTPUT_FILE
echo "Next steps:" | tee -a $OUTPUT_FILE
echo "1. Download both output files" | tee -a $OUTPUT_FILE
echo "2. Run analyze-terraform-state.sh in the state account" | tee -a $OUTPUT_FILE
echo "3. Use compare-resources.sh to find unmanaged resources" | tee -a $OUTPUT_FILE