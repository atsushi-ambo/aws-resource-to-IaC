# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an enhanced AWS resource discovery and Terraform state analysis toolkit designed to help identify unmanaged AWS resources and facilitate Infrastructure as Code (IaC) migration. The repository contains improved shell scripts with robust error handling, logging, and user experience enhancements.

## Key Scripts and Usage

### Main Toolkit Script (Recommended Entry Point)

```bash
# Run complete guided workflow
./aws-iac-toolkit.sh workflow

# Individual commands
./aws-iac-toolkit.sh discover [profile] [region]
./aws-iac-toolkit.sh analyze [state.json]
./aws-iac-toolkit.sh compare [aws.json] [terraform.json]
```

### Setup and Validation

```bash
# Validate setup and dependencies
./validate-setup.sh
# Checks AWS CLI, jq, credentials, and script permissions
```

### Core Discovery and Analysis Commands

```bash
# Discover all AWS resources with improved error handling
./discover-aws-resources.sh [OPTIONS] [profile] [region]
# Options: -h/--help, -v/--verbose, --no-color
# Output: aws-resources-YYYYMMDD-HHMMSS.json and .txt

# Analyze Terraform state files with enhanced validation
./analyze-terraform-state.sh [OPTIONS] [state.json]
# Options: -h/--help, -v/--verbose, --no-color
# Can process multiple state files or all *.json files in directory
# Output: terraform-resources-YYYYMMDD-HHMMSS.json and .txt

# Compare resources with better file detection
./compare-resources.sh [OPTIONS] [aws-resources.json] [terraform-resources.json]
# Options: -h/--help, -v/--verbose, --no-color
# Auto-detects latest files if not specified
# Output: unmanaged-resources-YYYYMMDD-HHMMSS.txt

# Compare US-East-1 specific resources (improved logic)
./compare_us_east_1.sh [aws-resources.json]
# Output: unmanaged-us-east-1-resources-YYYYMMDD-HHMMSS.txt

# Extract us-east-1 resources from Terraform state (fixed file detection)
./extract_us_east_resources.sh
# Output: terraform-us-east-1.json
```

## Architecture

### Workflow Pattern
1. **Resource Discovery**: `discover-aws-resources.sh` scans AWS account for all resources across services
2. **State Analysis**: `analyze-terraform-state.sh` extracts managed resources from Terraform state files
3. **Comparison**: `compare-resources.sh` identifies unmanaged resources by diffing the two datasets
4. **Specialized Analysis**: Region-specific scripts for services like CloudFront/ACM in us-east-1

### Data Flow
- AWS CLI queries generate structured JSON output files timestamped for tracking
- Terraform state files are parsed to extract resource IDs and types
- jq is used extensively for JSON processing and resource comparison
- Shell scripts generate both human-readable reports (.txt) and machine-readable JSON files

### Resource Categories Tracked
- **EC2**: Instances, Security Groups, VPCs, Subnets, Route Tables, NAT/Internet Gateways, Elastic IPs
- **RDS**: Database Instances, Clusters, Subnet Groups, Parameter Groups
- **Storage**: S3 Buckets, EBS Volumes
- **Networking**: Load Balancers, VPC Endpoints
- **Compute**: ECS Clusters, Services, Task Definitions
- **Security**: IAM Roles, ACM Certificates
- **Monitoring**: CloudWatch Log Groups
- **CDN**: CloudFront Distributions

## Dependencies and Improvements

### Requirements
- `jq` - JSON processor (install: `brew install jq`)
- AWS CLI configured with appropriate permissions
- Bash 4.0+ (for advanced features)

### Enhanced Features
- **Robust error handling**: All scripts use `set -euo pipefail` and comprehensive validation
- **Colorized logging**: Debug, info, warn, error levels with color coding
- **Dependency validation**: Scripts check for required tools before execution
- **AWS credential validation**: Verify credentials before attempting API calls
- **Progress indicators**: Long-running operations show progress
- **Help system**: All scripts support -h/--help for usage information
- **Safe AWS operations**: Enhanced safety wrapper blocks destructive operations
- **Improved file detection**: Better logic for finding state files vs generated reports
- **Guided workflow**: Main toolkit script provides step-by-step process

## File Naming Conventions

- `aws-resources-YYYYMMDD-HHMMSS.*` - AWS resource discovery output
- `terraform-resources-YYYYMMDD-HHMMSS.*` - Terraform state analysis output
- `unmanaged-resources-YYYYMMDD-HHMMSS.txt` - Resource comparison results
- `*.json` files - Terraform state files for analysis (typically environment-specific like dev.json, prod.json)

## Safety Features and Best Practices

### Safety Features
- **Enhanced read-only AWS wrapper**: Blocks destructive operations including attach/detach
- **Comprehensive validation**: JSON, file existence, permissions, and AWS credentials
- **Graceful error handling**: Scripts continue processing even if some queries fail
- **Auto-detection with validation**: Smart file detection with fallbacks
- **Dependency checking**: Validates all required tools before execution

### Development Best Practices
- All scripts follow consistent error handling patterns
- Logging functions provide structured output
- Variables are properly quoted and validated
- File operations use safe patterns
- Progress feedback for long-running operations
- Comprehensive help documentation

### Quick Start Workflow
1. Run `./validate-setup.sh` to check dependencies
2. Run `./aws-iac-toolkit.sh workflow` for guided process
3. Use individual scripts with `--help` for advanced usage