#!/usr/bin/env python3
"""
Production-grade Terraform VPC Generator for Jupyter/Colab
"""

import os
import json
import ipaddress
import yaml
from pathlib import Path
from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import (
    BaseModel, 
    Field, 
    field_validator, 
    ValidationError,
    ConfigDict,
    model_validator
)
from jinja2 import Template
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


class EnvironmentType(str, Enum):
    """Valid environment types for VPC tagging."""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    SANDBOX = "sandbox"


class VPCConfig(BaseModel):
    """Pydantic model for VPC configuration validation."""
    
    model_config = ConfigDict(
        extra='forbid',
        str_strip_whitespace=True,
        validate_default=True
    )
    
    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        pattern=r'^[a-zA-Z][a-zA-Z0-9_-]*$',
        description="VPC name"
    )
    
    cidr: str = Field(..., description="CIDR block for VPC")
    
    environment: Optional[EnvironmentType] = Field(
        default=EnvironmentType.DEVELOPMENT,
        description="Environment type"
    )
    
    enable_dns_hostnames: bool = Field(default=True)
    enable_dns_support: bool = Field(default=True)
    tags: Dict[str, str] = Field(default_factory=dict)
    region: Optional[str] = Field(default=None)
    
    @field_validator('cidr')
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        """Validate CIDR block against AWS VPC requirements."""
        try:
            network = ipaddress.ip_network(v, strict=False)
            
            if network.prefixlen < 16:
                raise ValueError(f"CIDR /{network.prefixlen} is too large. AWS VPCs support maximum size of /16")
            
            if network.prefixlen > 28:
                raise ValueError(f"CIDR /{network.prefixlen} is too small. AWS VPCs support minimum size of /28")
            
            if network.is_loopback or network.is_multicast or network.is_unspecified:
                raise ValueError(f"CIDR {v} is in a reserved IP range")
            
        except ValueError as e:
            if "has host bits set" not in str(e):
                raise ValueError(f"Invalid CIDR format: {str(e)}")
        
        return v
    
    @field_validator('name')
    @classmethod
    def validate_name_terraform(cls, v: str) -> str:
        """Validate name is Terraform-compatible."""
        reserved = {'null', 'true', 'false', 'var', 'local', 'module'}
        if v.lower() in reserved:
            raise ValueError(f"'{v}' is a Terraform reserved keyword")
        return v
    
    @model_validator(mode='after')
    def validate_tags(self) -> 'VPCConfig':
        """Ensure tags don't conflict with auto-generated ones."""
        reserved_tag_keys = {'Name', 'Environment', 'ManagedBy'}
        conflicts = reserved_tag_keys.intersection(self.tags.keys())
        if conflicts:
            raise ValueError(f"Tag keys {conflicts} are reserved and will be auto-generated")
        return self
    
    def to_terraform_tags(self) -> Dict[str, str]:
        """Generate Terraform-friendly tags dictionary."""
        tags = {
            "Name": self.name,
            "Environment": self.environment.value if self.environment else "development",
            "ManagedBy": "terraform-vpc-generator",
            "GeneratedAt": datetime.utcnow().isoformat()
        }
        tags.update(self.tags)
        return tags


class VPCCollection(BaseModel):
    """Container for multiple VPC configurations."""
    model_config = ConfigDict(extra='forbid')
    
    vpcs: List[VPCConfig] = Field(..., min_length=1, max_length=100)
    default_region: str = Field(default="us-east-1")
    output_directory: str = Field(default="terraform")
    
    @model_validator(mode='after')
    def apply_default_region(self) -> 'VPCCollection':
        """Apply default region to VPCs that don't specify one."""
        for vpc in self.vpcs:
            if vpc.region is None:
                vpc.region = self.default_region
        return self


class TerraformGenerator:
    """Handles Terraform file generation."""
    
    def __init__(self):
        self.template = self._get_template()
    
    def _get_template(self) -> Template:
        """Get Jinja2 template for VPC resources."""
        template_str = """# VPC: {{ vpc.name }}
resource "aws_vpc" "{{ vpc.name | replace('-', '_') }}" {
  cidr_block           = "{{ vpc.cidr }}"
  enable_dns_hostnames = {{ vpc.enable_dns_hostnames | lower }}
  enable_dns_support   = {{ vpc.enable_dns_support | lower }}
  
  tags = {
{% for key, value in vpc.to_terraform_tags().items() %}
    {{ key }} = "{{ value }}"
{% endfor %}
  }
}
"""
        return Template(template_str)
    
    def generate_vpc_file(self, vpc: VPCConfig) -> str:
        """Generate Terraform configuration for a single VPC."""
        return self.template.render(vpc=vpc)
    
    def generate_main_tf(self, collection: VPCCollection) -> str:
        """Generate complete main.tf file."""
        vpc_resources = []
        for vpc in collection.vpcs:
            vpc_resources.append(self.generate_vpc_file(vpc))
        
        # Generate outputs
        outputs = []
        for vpc in collection.vpcs:
            resource_name = vpc.name.replace("-", "_")
            outputs.append(f'    "{vpc.name}" = {{ id = aws_vpc.{resource_name}.id, cidr = aws_vpc.{resource_name}.cidr_block }}')
        
        main_tf = f"""# Auto-generated Terraform configuration
# Generated at: {datetime.utcnow().isoformat()}

terraform {{
  required_version = ">= 1.0"
  required_providers {{
    aws = {{
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }}
  }}
}}

provider "aws" {{
  region = "{collection.default_region}"
}}

{chr(10).join(vpc_resources)}

# Outputs
output "vpc_details" {{
  description = "Generated VPC details"
  value = {{
{chr(10).join(outputs)}
  }}
}}
"""
        return main_tf
    
    def generate_tfvars(self, collection: VPCCollection) -> Dict[str, Any]:
        """Generate terraform.tfvars compatible dictionary."""
        return {
            "vpcs": [
                {
                    "name": vpc.name,
                    "cidr": vpc.cidr,
                    "environment": vpc.environment.value if vpc.environment else "development",
                    "region": vpc.region
                }
                for vpc in collection.vpcs
            ]
        }
    
    def save_files(self, collection: VPCCollection) -> Path:
        """Save generated files to disk."""
        output_dir = Path(collection.output_directory)
        output_dir.mkdir(exist_ok=True)
        
        # Save main.tf
        main_tf_content = self.generate_main_tf(collection)
        main_tf_path = output_dir / "main.tf"
        main_tf_path.write_text(main_tf_content)
        print(f"✓ Saved: {main_tf_path}")
        
        # Save terraform.tfvars.json
        tfvars = self.generate_tfvars(collection)
        tfvars_path = output_dir / "terraform.tfvars.json"
        tfvars_path.write_text(json.dumps(tfvars, indent=2))
        print(f"✓ Saved: {tfvars_path}")
        
        # Save individual VPC files
        vpc_dir = output_dir / "vpcs"
        vpc_dir.mkdir(exist_ok=True)
        for vpc in collection.vpcs:
            vpc_file = vpc_dir / f"{vpc.name}.tf"
            vpc_file.write_text(self.generate_vpc_file(vpc))
            print(f"✓ Saved: {vpc_file}")
        
        return output_dir


def load_config_from_yaml(yaml_content: str) -> VPCCollection:
    """Load VPC configuration from YAML string."""
    try:
        data = yaml.safe_load(yaml_content)
        
        if isinstance(data, list):
            collection = VPCCollection(vpcs=data)
        elif isinstance(data, dict):
            collection = VPCCollection(**data)
        else:
            raise ValueError(f"Invalid YAML structure: expected list or dict, got {type(data)}")
        
        print(f"✓ Loaded {len(collection.vpcs)} VPC configurations")
        return collection
        
    except yaml.YAMLError as e:
        raise ValueError(f"Error parsing YAML: {str(e)}")
    except ValidationError as e:
        error_messages = []
        for error in e.errors():
            loc = " -> ".join(str(l) for l in error['loc'])
            error_messages.append(f"  • {loc}: {error['msg']}")
        raise ValueError(f"Validation failed:\n" + "\n".join(error_messages))


def run_vpc_generator(yaml_config: str = None):
    """Main function to run the VPC generator."""
    print("=" * 60)
    print("🚀 Terraform VPC Generator")
    print("=" * 60)
    
    # Use sample config if none provided
    if yaml_config is None:
        print("\n📝 Using sample configuration:")
        yaml_config = """
vpcs:
  - name: "production-vpc"
    cidr: "10.0.0.0/16"
    environment: "production"
    enable_dns_hostnames: true
    tags:
      CostCenter: "finance"
      Project: "core-infra"
    
  - name: "development-vpc"
    cidr: "10.1.0.0/16"
    environment: "development"
    enable_dns_hostnames: false
    tags:
      CostCenter: "engineering"
      Team: "platform"
    
  - name: "staging-vpc"
    cidr: "10.2.0.0/16"
    environment: "staging"
    region: "us-west-2"
"""
        print(yaml_config)
        print("-" * 60)
    
    try:
        # Load configuration
        print("\n📖 Loading configuration...")
        collection = load_config_from_yaml(yaml_config)
        
        # Display VPC configurations
        print("\n📋 VPC Configurations:")
        for i, vpc in enumerate(collection.vpcs, 1):
            print(f"\n  {i}. {vpc.name}")
            print(f"     - CIDR: {vpc.cidr}")
            print(f"     - Environment: {vpc.environment.value if vpc.environment else 'development'}")
            print(f"     - Region: {vpc.region}")
            print(f"     - DNS Hostnames: {vpc.enable_dns_hostnames}")
            if vpc.tags:
                print(f"     - Custom Tags: {vpc.tags}")
        
        # Generate files
        print("\n🔧 Generating Terraform files...")
        generator = TerraformGenerator()
        output_dir = generator.save_files(collection)
        
        # Display success message
        print("\n" + "=" * 60)
        print("✅ SUCCESS! Terraform configuration generated!")
        print("=" * 60)
        print(f"\n📁 Output directory: {output_dir.absolute()}")
        
        # Show generated files
        print("\n📄 Generated files:")
        for file in sorted(output_dir.glob("*")):
            if file.is_file():
                size = file.stat().st_size
                print(f"   - {file.name} ({size} bytes)")
        
        # Show subdirectory
        vpc_dir = output_dir / "vpcs"
        if vpc_dir.exists():
            print(f"\n📁 VPC individual files in: {vpc_dir.name}/")
            for file in sorted(vpc_dir.glob("*.tf")):
                print(f"   - vpcs/{file.name}")
        
        # Preview main.tf
        print("\n" + "=" * 60)
        print("📝 Preview of main.tf:")
        print("=" * 60)
        main_tf_path = output_dir / "main.tf"
        if main_tf_path.exists():
            content = main_tf_path.read_text()
            # Show first 50 lines or full content if shorter
            lines = content.split('\n')
            preview_lines = lines[:40]
            print('\n'.join(preview_lines))
            if len(lines) > 40:
                print(f"\n... and {len(lines) - 40} more lines")
        
        # Next steps
        print("\n" + "=" * 60)
        print("🚀 NEXT STEPS:")
        print("=" * 60)
        print(f"""
1. Navigate to the output directory:
   cd {output_dir.absolute()}

2. Initialize Terraform:
   terraform init

3. Review the plan:
   terraform plan

4. Apply the configuration:
   terraform apply

5. (Optional) Use variables file:
   terraform plan -var-file=terraform.tfvars.json

To download the generated files in Colab:
   - Click the folder icon in the left sidebar
   - Navigate to '{output_dir}'
   - Right-click and download files
""")
        
        return collection, output_dir
        
    except ValueError as e:
        print(f"\n❌ ERROR: {e}")
        raise
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        raise


# For direct execution in Colab
if __name__ == "__main__":
    # Run with sample configuration
    collection, output_dir = run_vpc_generator()
    
    # To use your own configuration, uncomment and modify:
    # custom_config = """
    # vpcs:
    #   - name: "my-vpc"
    #     cidr: "192.168.0.0/16"
    #     environment: "production"
    # """
    # collection, output_dir = run_vpc_generator(custom_config)
