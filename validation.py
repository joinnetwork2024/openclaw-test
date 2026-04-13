#!/usr/bin/env python3
import os
import re
import json
import ipaddress
import yaml
import warnings
from jinja2 import Environment, FileSystemLoader, TemplateError
from typing import List, Dict, Any
from pathlib import Path


def validate_vpc_config(vpc: Dict[str, Any]) -> bool:
    """Validate VPC configuration with proper Terraform naming rules."""
    
    # Validate VPC name
    name = vpc.get('name', '')
    if not name:
        raise ValueError("VPC name is required")
    
    if not isinstance(name, str):
        raise ValueError(f"VPC name must be a string, got {type(name)}")
    
    # Terraform allows: letters, numbers, underscores, and hyphens
    # Must start with a letter or underscore
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_-]*$', name):
        raise ValueError(
            f"VPC name '{name}' is invalid. "
            "Terraform names must start with a letter or underscore, "
            "and contain only letters, numbers, underscores, and hyphens."
        )
    
    # Validate CIDR block
    cidr = vpc.get('cidr', '')
    if not cidr:
        raise ValueError(f"CIDR block is required for VPC '{name}'")
    
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        
        if network.prefixlen < 12 or network.prefixlen > 28:
            raise ValueError(
                f"CIDR prefix length for VPC '{name}' should be between /12 and /28, "
                f"got /{network.prefixlen}"
            )
        
        if not network.is_private:
            warnings.warn(
                f"VPC '{name}' uses public IP range {cidr}. "
                "Consider using private IP ranges",
                UserWarning
            )
        
    except ValueError as e:
        raise ValueError(f"Invalid CIDR '{cidr}' for VPC '{name}': {str(e)}")
    
    return True


def load_vpc_config(config_path: str) -> List[Dict[str, Any]]:
    """Load and validate VPC configuration from YAML file."""
    config_file = Path(config_path)
    
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    try:
        with open(config_file, 'r') as f:
            vpcs = yaml.safe_load(f)
        
        if not isinstance(vpcs, list):
            raise ValueError(f"Expected YAML list, got {type(vpcs)}")
        
        for vpc in vpcs:
            validate_vpc_config(vpc)
        
        return vpcs
        
    except yaml.YAMLError as e:
        raise ValueError(f"Error parsing YAML: {str(e)}")


def generate_tfvars_file(vpcs: List[Dict[str, Any]]) -> None:
    """Generate terraform.tfvars.json file."""
    tfvars = {"vpcs": vpcs}
    
    os.makedirs("terraform", exist_ok=True)
    
    with open("terraform/terraform.tfvars.json", "w") as f:
        json.dump(tfvars, f, indent=2)
    
    print(f"✓ Generated: terraform/terraform.tfvars.json")


def generate_terraform_resources(config_path: str) -> None:
    """Main function to generate Terraform resources."""
    print(f"Loading configuration from: {config_path}")
    vpcs = load_vpc_config(config_path)
    print(f"✓ Loaded {len(vpcs)} VPC configurations")
    
    print("\nGenerating terraform.tfvars.json file...")
    generate_tfvars_file(vpcs)
    
    # Generate sample main.tf
    with open("terraform/main.tf", "w") as f:
        f.write("""# Terraform configuration using dynamic VPCs from YAML
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "vpcs" {
  description = "VPC configurations loaded from YAML"
  type = list(object({
    name = string
    cidr = string
  }))
}

resource "aws_vpc" "this" {
  for_each = { for vpc in var.vpcs : vpc.name => vpc }
  
  cidr_block = each.value.cidr
  tags = {
    Name        = each.value.name
    Environment = "dynamic"
    ManagedBy   = "python-yaml-jinja2"
  }
}

output "vpc_ids" {
  description = "Map of VPC names to IDs"
  value = { for k, v in aws_vpc.this : k => v.id }
}
""")
    
    print("✓ Generated: terraform/main.tf")
    print("\n" + "="*50)
    print("✅ Terraform configuration generated successfully!")
    print("="*50)
    print("\nNext steps:")
    print("1. cd terraform")
    print("2. terraform init")
    print("3. terraform plan -var-file=terraform.tfvars.json")
    print("4. terraform apply -var-file=terraform.tfvars.json")


def main():
    """Main entry point."""
    try:
        generate_terraform_resources("vpcs.yaml")
        
    except FileNotFoundError as e:
        print(f"❌ Error: {e}")
        print("\nCreate vpcs.yaml with:")
        print("""
- name: "main-vpc"
  cidr: "10.0.0.0/16"
- name: "dev-vpc"
  cidr: "172.16.0.0/12"
- name: "prod-vpc"
  cidr: "192.168.0.0/16"
        """)
        
    except ValueError as e:
        print(f"❌ Configuration error: {e}")
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


if __name__ == "__main__":
    main()
