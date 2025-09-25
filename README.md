# AWS Resource to Infrastructure as Code (IaC) Toolkit

A comprehensive toolkit for discovering AWS resources and identifying what needs to be imported into Terraform. This collection of shell scripts helps bridge the gap between existing AWS infrastructure and Infrastructure as Code management.

## Overview

This toolkit follows a systematic approach to help with IaC migration:

1. **Discover** - Scan AWS account for all existing resources
2. **Analyze** - Extract resources already managed by Terraform
3. **Compare** - Identify unmanaged resources that need importing
4. **Report** - Generate actionable reports for infrastructure teams

## Prerequisites

- **AWS CLI** configured with appropriate read permissions
- **jq** JSON processor: `brew install jq` (macOS) or `apt install jq` (Ubuntu)
- Bash shell environment

## 🎯 Main Toolkit Script (Start Here)

### 🚀 `aws-iac-toolkit.sh`
**New!** Unified entry point with guided workflow - the easiest way to use this toolkit.

```bash
./aws-iac-toolkit.sh workflow                    # Run complete guided workflow
./aws-iac-toolkit.sh discover [profile] [region] # Individual discovery step
./aws-iac-toolkit.sh analyze [state.json]        # Individual analysis step
./aws-iac-toolkit.sh compare                     # Individual comparison step
./aws-iac-toolkit.sh help                        # Show help
```

### 🔍 `validate-setup.sh`
**New!** Validates your setup and checks all prerequisites before running the toolkit.

```bash
./validate-setup.sh                              # Check dependencies and setup
```

**Checks:** AWS CLI installation, jq availability, AWS credentials, script permissions, and Terraform state files.

## Core Scripts

### 🔍 `discover-aws-resources.sh`
Discovers all AWS resources across your account and region.

```bash
./discover-aws-resources.sh [profile] [region]

# Examples:
./discover-aws-resources.sh                    # Uses default profile and us-east-1
./discover-aws-resources.sh production         # Uses production profile
./discover-aws-resources.sh staging us-west-2  # Uses staging profile in us-west-2
```

**Output:**
- `aws-resources-YYYYMMDD-HHMMSS.txt` - Human-readable report
- `aws-resources-YYYYMMDD-HHMMSS.json` - Machine-readable data

**Covers:** EC2, VPC, RDS, S3, ECS, IAM, CloudWatch, ACM, Secrets Manager, and more.

### 📊 `analyze-terraform-state.sh`
Analyzes Terraform state files to identify currently managed resources.

```bash
./analyze-terraform-state.sh [state.json]

# Examples:
./analyze-terraform-state.sh                    # Processes all *.json files in directory
./analyze-terraform-state.sh prod.tfstate.json  # Processes specific state file
```

**Output:**
- `terraform-resources-YYYYMMDD-HHMMSS.txt` - Human-readable consolidated report
- `terraform-resources-YYYYMMDD-HHMMSS.json` - Machine-readable consolidated data

### 🔄 `compare-resources.sh`
Compares AWS resources with Terraform-managed resources to find gaps.

```bash
./compare-resources.sh [aws-file.json] [terraform-file.json]

# Examples:
./compare-resources.sh                          # Auto-detects latest files
./compare-resources.sh aws.json terraform.json # Uses specific files
```

**Output:**
- `unmanaged-resources-YYYYMMDD-HHMMSS.txt` - List of unmanaged resources

### 🌐 `compare_us_east_1.sh`
Specialized comparison for us-east-1 resources (CloudFront, ACM certificates).

```bash
./compare_us_east_1.sh [aws-resources.json]
```

**Output:**
- `unmanaged-us-east-1-resources-YYYYMMDD-HHMMSS.txt`

### 📤 `extract_us_east_resources.sh`
Extracts us-east-1 specific resources from Terraform state.

```bash
./extract_us_east_resources.sh
```

**Output:**
- `terraform-us-east-1.json`

## Quick Start

### Option 1: Guided Workflow (Recommended)
```bash
# Step 1: Validate your setup first (NEW!)
./validate-setup.sh

# Step 2: Run the complete guided workflow (NEW!)
./aws-iac-toolkit.sh workflow
```

This new guided workflow will:
1. Ask for your AWS profile and region
2. Automatically discover all AWS resources
3. Analyze your Terraform state files
4. Compare and generate unmanaged resource reports
5. Provide next steps for importing resources

### Option 2: Manual Steps
1. **Discover your AWS resources:**
   ```bash
   ./discover-aws-resources.sh production us-east-1
   ```

2. **Analyze your Terraform state:**
   ```bash
   # Place your state files (dev.json, prod.json, etc.) in the directory
   ./analyze-terraform-state.sh
   ```

3. **Find unmanaged resources:**
   ```bash
   ./compare-resources.sh
   ```

4. **Review the reports** and plan your Terraform import strategy

### Getting Help
All scripts now support enhanced help and options:
```bash
./aws-iac-toolkit.sh --help              # Main toolkit help
./validate-setup.sh                      # Setup validation
./discover-aws-resources.sh --help       # Discovery script help
./analyze-terraform-state.sh --help      # Analysis script help
./compare-resources.sh --help            # Comparison script help

# All scripts support these options:
--help                                    # Show detailed help
--verbose                                # Enable verbose logging
--no-color                               # Disable colored output
```

## Enhanced Features

- ✅ **Read-only operations**: Enhanced safety wrappers prevent accidental AWS modifications
- ✅ **Comprehensive validation**: JSON, credentials, dependencies, and file permissions
- ✅ **Colorized logging**: Debug, info, warning, and error levels with color coding
- ✅ **Progress indicators**: Visual feedback for long-running operations
- ✅ **Guided workflow**: Step-by-step process with the main toolkit script
- ✅ **Smart file detection**: Improved logic for finding state files vs generated reports
- ✅ **Help system**: Every script supports `--help` with detailed usage
- ✅ **Setup validation**: `validate-setup.sh` checks all prerequisites
- ✅ **Error recovery**: Scripts handle failures gracefully and continue processing

## Resource Coverage

The toolkit comprehensively covers AWS services including:

- **Compute**: EC2 instances, ECS clusters/services
- **Networking**: VPCs, subnets, security groups, load balancers, NAT gateways
- **Storage**: S3 buckets, EBS volumes
- **Database**: RDS instances, clusters, ElastiCache
- **Security**: IAM roles, ACM certificates, Secrets Manager
- **Monitoring**: CloudWatch log groups
- **CDN**: CloudFront distributions

## Output Files

All scripts generate timestamped files to track analysis progression:

- `aws-resources-*` - AWS discovery results
- `terraform-resources-*` - Terraform state analysis
- `unmanaged-resources-*` - Resource gap analysis
- `*.json` files - Machine-readable data for programmatic use
- `*.txt` files - Human-readable reports for manual review

## Contributing

This toolkit is designed to be extended. When adding new AWS services:

1. Add resource discovery logic to `discover-aws-resources.sh`
2. Add resource extraction logic to `analyze-terraform-state.sh`
3. Add comparison logic to `compare-resources.sh`
4. Update resource coverage documentation

## All Scripts Summary

| Script | Purpose | New Features |
|--------|---------|--------------|
| `aws-iac-toolkit.sh` | **NEW!** Main orchestration script | Guided workflow, unified interface |
| `validate-setup.sh` | **NEW!** Setup validation | Dependency checking, credential validation |
| `discover-aws-resources.sh` | AWS resource discovery | Enhanced error handling, progress indicators, colored logging |
| `analyze-terraform-state.sh` | Terraform state analysis | Improved file detection, better validation |
| `compare-resources.sh` | Resource comparison | Smart auto-detection, enhanced reporting |
| `compare_us_east_1.sh` | US-East-1 specific comparison | Fixed logic for CloudFront/ACM resources |
| `extract_us_east_resources.sh` | Extract US-East-1 resources | Improved file pattern matching |

## Files Generated

- `aws-resources-YYYYMMDD-HHMMSS.*` - AWS discovery results
- `terraform-resources-YYYYMMDD-HHMMSS.*` - Terraform state analysis
- `unmanaged-resources-YYYYMMDD-HHMMSS.txt` - Resources needing import
- `unmanaged-us-east-1-resources-YYYYMMDD-HHMMSS.txt` - US-East-1 specific results

## License

This project is open source and available under standard licensing terms.