import boto3
import os
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from dotenv import load_dotenv
from logger_config import AWSLogger
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from tabulate import tabulate


class AWSPublicResourceScanner:
    def __init__(self):
        # Load environment variables
        load_dotenv()
        
        # Initialize logger
        log_file = os.getenv('LOG_FILE', 'logs/aws_public_resources.log')
        log_level = os.getenv('LOG_LEVEL', 'INFO')
        self.logger = AWSLogger(log_file, log_level).get_logger()
        
        # Configuration
        self.max_workers = int(os.getenv('MAX_WORKERS', 10))
        self.timeout = int(os.getenv('TIMEOUT_SECONDS', 30))
        self.services_to_scan = os.getenv('SERVICES_TO_SCAN', 'ec2,rds,elb,s3').split(',')
        
        # Results storage
        self.public_resources = []
        self.total_resources = 0
        
        # Initialize AWS session
        self.session = self._initialize_session()
    
    def _initialize_session(self):
        """Initialize AWS session with credentials from environment or SSO"""
        try:
            # Option 1: Try AWS Profile (includes SSO)
            aws_profile = os.getenv('AWS_PROFILE')
            if aws_profile:
                self.logger.info(f"🔑 Using AWS Profile: {aws_profile}")
                session = boto3.Session(profile_name=aws_profile)
            else:
                # Option 2: Try environment variables
                access_key = os.getenv('AWS_ACCESS_KEY_ID')
                secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
                session_token = os.getenv('AWS_SESSION_TOKEN')
                
                if access_key and secret_key:
                    self.logger.info("🔑 Using environment variables credentials")
                    session = boto3.Session(
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret_key,
                        aws_session_token=session_token,
                        region_name=os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
                    )
                else:
                    # Option 3: Try default credential chain (includes SSO)
                    self.logger.info("🔑 Using default AWS credential chain")
                    session = boto3.Session(
                        region_name=os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
                    )
            
            # Test credentials
            sts = session.client('sts')
            identity = sts.get_caller_identity()
            self.logger.info(f"✅ Authenticated as: {identity.get('Arn', 'Unknown')}")
            return session
            
        except (NoCredentialsError, PartialCredentialsError) as e:
            self.logger.error(f"❌ Credentials error: {str(e)}")
            self.logger.error("💡 Try: aws sso login --profile your-profile")
            raise
        except Exception as e:
            self.logger.error(f"❌ Error initializing AWS session: {str(e)}")
            raise
    
    def get_all_regions(self):
        """Get all available AWS regions"""
        try:
            ec2 = self.session.client('ec2')
            regions = ec2.describe_regions()
            return [region['RegionName'] for region in regions['Regions']]
        except Exception as e:
            self.logger.error(f"❌ Error getting regions: {str(e)}")
            return [os.getenv('AWS_DEFAULT_REGION', 'us-east-1')]
    
    def scan_ec2_instances(self, region):
        """Scan EC2 instances for public exposure"""
        try:
            ec2 = self.session.client('ec2', region_name=region)
            self.logger.info(f"🔍 Scanning EC2 instances in {region}")
            
            paginator = ec2.get_paginator('describe_instances')
            resources_found = 0
            
            for page in paginator.paginate():
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        resources_found += 1
                        
                        # Check if instance has public IP
                        public_ip = instance.get('PublicIpAddress')
                        public_dns = instance.get('PublicDnsName')
                        
                        if public_ip or public_dns:
                            # Get security groups
                            security_groups = instance.get('SecurityGroups', [])
                            open_ports = self._check_security_groups(ec2, security_groups)
                            
                            self.public_resources.append({
                                'Service': 'EC2',
                                'Region': region,
                                'ResourceId': instance['InstanceId'],
                                'Type': 'Instance',
                                'PublicIP': public_ip or 'N/A',
                                'PublicDNS': public_dns or 'N/A',
                                'OpenPorts': ', '.join(open_ports),
                                'State': instance['State']['Name']
                            })
                            
                            self.logger.warning(f"🌐 Public EC2 instance: {instance['InstanceId']} ({public_ip}) with ports: {open_ports}")
            
            self.total_resources += resources_found
            self.logger.info(f"✅ EC2 {region}: {resources_found} instances scanned")
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['UnauthorizedOperation', 'AccessDenied']:
                self.logger.warning(f"⚠️ No permissions for EC2 in {region}: {str(e)}")
            else:
                self.logger.error(f"❌ Error scanning EC2 in {region}: {str(e)}")
        except Exception as e:
            self.logger.error(f"❌ Unexpected error in EC2 {region}: {str(e)}")
    
    def _check_security_groups(self, ec2_client, security_groups):
        """Check security groups for open ports"""
        open_ports = []
        
        try:
            sg_ids = [sg['GroupId'] for sg in security_groups]
            if not sg_ids:
                return open_ports
            
            response = ec2_client.describe_security_groups(GroupIds=sg_ids)
            
            for sg in response['SecurityGroups']:
                for rule in sg.get('IpPermissions', []):
                    # Check if rule allows traffic from anywhere (0.0.0.0/0)
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            from_port = rule.get('FromPort', 'All')
                            to_port = rule.get('ToPort', 'All')
                            protocol = rule.get('IpProtocol', 'All')
                            
                            if from_port == to_port:
                                port_str = f"{from_port}/{protocol}"
                            else:
                                port_str = f"{from_port}-{to_port}/{protocol}"
                            
                            open_ports.append(port_str)
        
        except Exception as e:
            self.logger.error(f"❌ Error checking security groups: {str(e)}")
        
        return list(set(open_ports))  # Remove duplicates
    
    def scan_rds_instances(self, region):
        """Scan RDS instances for public exposure"""
        try:
            rds = self.session.client('rds', region_name=region)
            self.logger.info(f"🔍 Scanning RDS instances in {region}")
            
            paginator = rds.get_paginator('describe_db_instances')
            resources_found = 0
            
            for page in paginator.paginate():
                for instance in page['DBInstances']:
                    resources_found += 1
                    
                    if instance.get('PubliclyAccessible', False):
                        endpoint = instance.get('Endpoint', {})
                        
                        self.public_resources.append({
                            'Service': 'RDS',
                            'Region': region,
                            'ResourceId': instance['DBInstanceIdentifier'],
                            'Type': 'Database',
                            'PublicIP': 'N/A',
                            'PublicDNS': endpoint.get('Address', 'N/A'),
                            'OpenPorts': str(endpoint.get('Port', 'N/A')),
                            'State': instance['DBInstanceStatus']
                        })
                        
                        self.logger.warning(f"🌐 Public RDS database: {instance['DBInstanceIdentifier']}")
            
            self.total_resources += resources_found
            self.logger.info(f"✅ RDS {region}: {resources_found} instances scanned")
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['UnauthorizedOperation', 'AccessDenied']:
                self.logger.warning(f"⚠️ No permissions for RDS in {region}: {str(e)}")
            else:
                self.logger.error(f"❌ Error scanning RDS in {region}: {str(e)}")
        except Exception as e:
            self.logger.error(f"❌ Unexpected error in RDS {region}: {str(e)}")
    
    def scan_load_balancers(self, region):
        """Scan ELB/ALB/NLB for public exposure"""
        try:
            # Classic Load Balancers
            elb = self.session.client('elb', region_name=region)
            self.logger.info(f"🔍 Scanning Classic Load Balancers in {region}")
            
            response = elb.describe_load_balancers()
            for lb in response['LoadBalancers']:
                self.total_resources += 1
                
                if lb.get('Scheme') == 'internet-facing':
                    listeners = [f"{l['Protocol']}:{l['LoadBalancerPort']}" for l in lb['ListenerDescriptions']]
                    
                    self.public_resources.append({
                        'Service': 'ELB',
                        'Region': region,
                        'ResourceId': lb['LoadBalancerName'],
                        'Type': 'Classic Load Balancer',
                        'PublicIP': 'N/A',
                        'PublicDNS': lb['DNSName'],
                        'OpenPorts': ', '.join(listeners),
                        'State': 'active'
                    })
                    
                    self.logger.warning(f"🌐 Public Load Balancer: {lb['LoadBalancerName']}")
            
            # Application/Network Load Balancers
            elbv2 = self.session.client('elbv2', region_name=region)
            self.logger.info(f"🔍 Scanning ALB/NLB in {region}")
            
            response = elbv2.describe_load_balancers()
            for lb in response['LoadBalancers']:
                self.total_resources += 1
                
                if lb.get('Scheme') == 'internet-facing':
                    self.public_resources.append({
                        'Service': 'ELBv2',
                        'Region': region,
                        'ResourceId': lb['LoadBalancerName'],
                        'Type': lb['Type'].upper(),
                        'PublicIP': 'N/A',
                        'PublicDNS': lb['DNSName'],
                        'OpenPorts': 'HTTP/HTTPS',
                        'State': lb['State']['Code']
                    })
                    
                    self.logger.warning(f"🌐 Public {lb['Type'].upper()}: {lb['LoadBalancerName']}")
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['UnauthorizedOperation', 'AccessDenied']:
                self.logger.warning(f"⚠️ No permissions for ELB in {region}: {str(e)}")
            else:
                self.logger.error(f"❌ Error scanning ELB in {region}: {str(e)}")
        except Exception as e:
            self.logger.error(f"❌ Unexpected error in ELB {region}: {str(e)}")
    
    def scan_s3_buckets(self):
        """Scan S3 buckets for public access"""
        try:
            s3 = self.session.client('s3')
            self.logger.info("🔍 Scanning S3 buckets")
            
            response = s3.list_buckets()
            
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                self.total_resources += 1
                
                try:
                    # Check bucket ACL
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    is_public = False
                    
                    for grant in acl['Grants']:
                        grantee = grant.get('Grantee', {})
                        if grantee.get('Type') == 'Group' and 'AllUsers' in grantee.get('URI', ''):
                            is_public = True
                            break
                    
                    # Check bucket policy
                    try:
                        policy = s3.get_bucket_policy(Bucket=bucket_name)
                        # Simple check for public access in policy
                        if '"Principal": "*"' in policy['Policy']:
                            is_public = True
                    except ClientError:
                        pass  # No policy or access denied
                    
                    if is_public:
                        self.public_resources.append({
                            'Service': 'S3',
                            'Region': 'global',
                            'ResourceId': bucket_name,
                            'Type': 'Bucket',
                            'PublicIP': 'N/A',
                            'PublicDNS': f"{bucket_name}.s3.amazonaws.com",
                            'OpenPorts': 'HTTP/HTTPS',
                            'State': 'active'
                        })
                        
                        self.logger.warning(f"🌐 Public S3 bucket: {bucket_name}")
                
                except ClientError as e:
                    if e.response['Error']['Code'] == 'AccessDenied':
                        self.logger.warning(f"⚠️ No permissions for bucket {bucket_name}")
                    else:
                        self.logger.error(f"❌ Error checking bucket {bucket_name}: {str(e)}")
            
            self.logger.info(f"✅ S3: {len(response['Buckets'])} buckets scanned")
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['UnauthorizedOperation', 'AccessDenied']:
                self.logger.warning(f"⚠️ No permissions for S3: {str(e)}")
            else:
                self.logger.error(f"❌ Error scanning S3: {str(e)}")
        except Exception as e:
            self.logger.error(f"❌ Unexpected error in S3: {str(e)}")
    
    def scan_region(self, region):
        """Scan all services in a specific region"""
        self.logger.info(f"🌍 Starting scan of region: {region}")
        
        service_functions = {
            'ec2': self.scan_ec2_instances,
            'rds': self.scan_rds_instances,
            'elb': self.scan_load_balancers
        }
        
        for service in self.services_to_scan:
            if service in service_functions:
                try:
                    service_functions[service](region)
                except Exception as e:
                    self.logger.error(f"❌ Error in service {service} region {region}: {str(e)}")
    
    def run_scan(self):
        """Run the complete scan across all regions and services"""
        start_time = time.time()
        self.logger.info("🚀 Starting AWS public resources scan")
        
        try:
            # Get all regions
            regions = self.get_all_regions()
            self.logger.info(f"📍 Scanning {len(regions)} regions")
            
            # Scan S3 (global service)
            if 's3' in self.services_to_scan:
                self.scan_s3_buckets()
            
            # Scan regional services
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_region = {executor.submit(self.scan_region, region): region for region in regions}
                
                for future in as_completed(future_to_region):
                    region = future_to_region[future]
                    try:
                        future.result()
                    except Exception as e:
                        self.logger.error(f"❌ Error completing scan of region {region}: {str(e)}")
            
            # Generate report
            self.generate_report()
            
            scan_time = time.time() - start_time
            self.logger.info(f"📊 Scan completed in {scan_time:.2f} seconds")
            self.logger.info(f"📊 Total resources: {self.total_resources}, Public resources: {len(self.public_resources)}")
            
        except Exception as e:
            self.logger.error(f"❌ Critical error during scan: {str(e)}")
            raise
    
    def generate_report(self):
        """Generate a formatted report of public resources"""
        if not self.public_resources:
            self.logger.info("✅ Excellent! No public resources found")
            return
        
        # Console table
        headers = ['Service', 'Region', 'Resource ID', 'Type', 'Public DNS', 'Open Ports', 'State']
        table_data = []
        
        for resource in self.public_resources:
            table_data.append([
                resource['Service'],
                resource['Region'],
                resource['ResourceId'][:30],  # Truncate long IDs
                resource['Type'],
                resource['PublicDNS'][:40],  # Truncate long DNS
                resource['OpenPorts'][:20],  # Truncate long port lists
                resource['State']
            ])
        
        print("\n" + "="*100)
        print("🌐 PUBLIC RESOURCES FOUND")
        print("="*100)
        print(tabulate(table_data, headers=headers, tablefmt='grid'))
        print("="*100)
        
        # Save JSON report
        report_file = f"logs/public_resources_report_{int(time.time())}.json"
        os.makedirs(os.path.dirname(report_file), exist_ok=True)
        
        with open(report_file, 'w') as f:
            json.dump({
                'scan_timestamp': time.time(),
                'total_resources_scanned': self.total_resources,
                'public_resources_found': len(self.public_resources),
                'public_resources': self.public_resources
            }, f, indent=2)
        
        self.logger.info(f"📄 Report saved to: {report_file}")


if __name__ == "__main__":
    try:
        scanner = AWSPublicResourceScanner()
        scanner.run_scan()
    except KeyboardInterrupt:
        print("\n⏹️ Scan interrupted by user")
    except Exception as e:
        print(f"\n❌ Critical error: {str(e)}")
        exit(1)
