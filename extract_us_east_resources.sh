#!/bin/bash

set -e

# Extract us-east-1 resources from Terraform state
echo "Extracting us-east-1 resources from Terraform state files..."

# CloudFront distributions
echo "CloudFront distributions in Terraform:"
TERRAFORM_CF=$(find . -maxdepth 1 -name "*.json" -type f ! -name "aws-resources-*" ! -name "terraform-resources-*" ! -name "unmanaged-*" -exec jq -r '.resources[]? | select(.type == "aws_cloudfront_distribution") | .instances[]?.attributes.id' {} \; 2>/dev/null | sort | uniq)
echo "$TERRAFORM_CF" | wc -l | tr -d ' '
echo "$TERRAFORM_CF"

echo ""
echo "ACM certificates in Terraform (us-east-1):"
# ACM certificates - they might have region info in provider
TERRAFORM_ACM=$(find . -maxdepth 1 -name "*.json" -type f ! -name "aws-resources-*" ! -name "terraform-resources-*" ! -name "unmanaged-*" -exec jq -r '.resources[]? | select(.type == "aws_acm_certificate") | .instances[]?.attributes.arn' {} \; 2>/dev/null | grep "us-east-1" | sort | uniq)
if [ -z "$TERRAFORM_ACM" ]; then
  echo "0"
else
  echo "$TERRAFORM_ACM" | wc -l | tr -d ' '
  echo "$TERRAFORM_ACM"
fi

# Save to JSON for comparison
echo "{" > terraform-us-east-1.json
echo '  "cloudfront_distributions": [' >> terraform-us-east-1.json
echo "$TERRAFORM_CF" | sed 's/^/    "/' | sed 's/$/"/' | paste -sd, >> terraform-us-east-1.json
echo "  ]," >> terraform-us-east-1.json
echo '  "acm_certificates": [' >> terraform-us-east-1.json
if [ -n "$TERRAFORM_ACM" ]; then
  echo "$TERRAFORM_ACM" | sed 's/^/    "/' | sed 's/$/"/' | paste -sd, >> terraform-us-east-1.json
fi
echo "  ]" >> terraform-us-east-1.json
echo "}" >> terraform-us-east-1.json

echo ""
echo "Saved to terraform-us-east-1.json"
