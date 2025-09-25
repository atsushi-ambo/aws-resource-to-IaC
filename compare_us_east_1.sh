#!/bin/bash

set -e

# Accept AWS file as parameter or auto-detect
AWS_FILE="${1:-}"

if [ -z "$AWS_FILE" ]; then
    AWS_FILE=$(ls -t aws-resources-*.json 2>/dev/null | head -1)
    if [ -z "$AWS_FILE" ]; then
        echo "Error: No AWS resources file found"
        echo "Usage: $0 [aws-resources.json]"
        echo "Or run discover-aws-resources.sh first to generate aws-resources-*.json"
        exit 1
    fi
    echo "Using AWS resources file: $AWS_FILE"
fi

if [ ! -f "$AWS_FILE" ]; then
    echo "Error: AWS file not found: $AWS_FILE"
    exit 1
fi

OUTPUT_FILE="unmanaged-us-east-1-resources-$(date +%Y%m%d-%H%M%S).txt"

echo "US-EAST-1 RESOURCE COMPARISON REPORT" | tee $OUTPUT_FILE
echo "====================================" | tee -a $OUTPUT_FILE
echo "Date: $(date)" | tee -a $OUTPUT_FILE
echo "AWS Resources File: $AWS_FILE" | tee -a $OUTPUT_FILE
echo "" | tee -a $OUTPUT_FILE

# CloudFront Distributions
echo "CLOUDFRONT DISTRIBUTIONS" | tee -a $OUTPUT_FILE
echo "------------------------" | tee -a $OUTPUT_FILE

# Get CloudFront from AWS discovery
AWS_CF=$(jq -r '.cloudfront_distributions[]' "$AWS_FILE" 2>/dev/null | sort | uniq)
AWS_CF_COUNT=$(echo "$AWS_CF" | grep -v "^$" | wc -l | tr -d ' ')

# Get CloudFront from Terraform - look in terraform state files, not generated reports
TF_CF=$(find . -maxdepth 1 -name "*.json" -type f ! -name "aws-resources-*" ! -name "terraform-resources-*" ! -name "unmanaged-*" -exec jq -r '.resources[]? | select(.type == "aws_cloudfront_distribution") | .instances[]?.attributes.id' {} \; 2>/dev/null | sort | uniq)
TF_CF_COUNT=$(echo "$TF_CF" | grep -v "^$" | wc -l | tr -d ' ')

echo "AWS has: $AWS_CF_COUNT distributions" | tee -a $OUTPUT_FILE
echo "Terraform manages: $TF_CF_COUNT distributions" | tee -a $OUTPUT_FILE

# Find unmanaged CloudFront distributions
echo "" | tee -a $OUTPUT_FILE
echo "Unmanaged CloudFront distributions (in AWS but not in Terraform):" | tee -a $OUTPUT_FILE
for dist in $AWS_CF; do
  if ! echo "$TF_CF" | grep -q "^$dist$"; then
    echo "  - $dist" | tee -a $OUTPUT_FILE
  fi
done

# ACM Certificates
echo "" | tee -a $OUTPUT_FILE
echo "ACM CERTIFICATES (us-east-1)" | tee -a $OUTPUT_FILE
echo "----------------------------" | tee -a $OUTPUT_FILE

# Get unique ACM certs from AWS
AWS_ACM=$(jq -r '.acm_certificates[]' "$AWS_FILE" 2>/dev/null | sort | uniq)
AWS_ACM_COUNT=$(echo "$AWS_ACM" | grep -v "^$" | wc -l | tr -d ' ')

# Check if any ACM certs in Terraform (checking all state files)
TF_ACM=$(find . -maxdepth 1 -name "*.json" -type f ! -name "aws-resources-*" ! -name "terraform-resources-*" ! -name "unmanaged-*" -exec jq -r '.resources[]? | select(.type == "aws_acm_certificate" or .type == "aws_acm_certificate_validation") | .instances[]?.attributes.arn // .instances[]?.attributes.certificate_arn' {} \; 2>/dev/null | grep -E "us-east-1|arn:aws:acm:us-east-1" | sort | uniq)
TF_ACM_COUNT=$(echo "$TF_ACM" | grep -v "^$" | wc -l | tr -d ' ')
if [ -z "$TF_ACM" ]; then
  TF_ACM_COUNT=0
fi

echo "AWS has: $AWS_ACM_COUNT certificates" | tee -a $OUTPUT_FILE
echo "Terraform manages: $TF_ACM_COUNT certificates" | tee -a $OUTPUT_FILE

echo "" | tee -a $OUTPUT_FILE
echo "Unmanaged ACM certificates (in AWS but not in Terraform):" | tee -a $OUTPUT_FILE
if [[ "$TF_ACM_COUNT" -eq 0 ]]; then
  echo "  ALL $AWS_ACM_COUNT certificates are unmanaged!" | tee -a $OUTPUT_FILE
  if [[ $AWS_ACM_COUNT -gt 10 ]]; then
    echo "$AWS_ACM" | head -10 | sed 's/^/  - /' | tee -a $OUTPUT_FILE
    echo "  ... and $(($AWS_ACM_COUNT - 10)) more" | tee -a $OUTPUT_FILE
  else
    echo "$AWS_ACM" | sed 's/^/  - /' | tee -a $OUTPUT_FILE
  fi
else
  for cert in $AWS_ACM; do
    if ! echo "$TF_ACM" | grep -q "$cert"; then
      echo "  - $cert" | tee -a $OUTPUT_FILE
    fi
  done
fi

# Summary
echo "" | tee -a $OUTPUT_FILE
echo "SUMMARY" | tee -a $OUTPUT_FILE
echo "-------" | tee -a $OUTPUT_FILE
UNMANAGED_CF=$((AWS_CF_COUNT - TF_CF_COUNT))
UNMANAGED_ACM=$((AWS_ACM_COUNT - TF_ACM_COUNT))
echo "Total unmanaged CloudFront distributions: $UNMANAGED_CF out of $AWS_CF_COUNT" | tee -a $OUTPUT_FILE
echo "Total unmanaged ACM certificates: $UNMANAGED_ACM out of $AWS_ACM_COUNT" | tee -a $OUTPUT_FILE
echo "" | tee -a $OUTPUT_FILE
echo "Note: CloudFront and its ACM certificates must be in us-east-1 region" | tee -a $OUTPUT_FILE
echo "" | tee -a $OUTPUT_FILE
echo "Results saved to: $OUTPUT_FILE"