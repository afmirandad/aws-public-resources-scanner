# AWS Public Resources Scanner

This project scans AWS resources that are publicly exposed to the internet, identifying potential security vulnerabilities.

## 🚀 Features

- **Multi-Service Scanning**: EC2, RDS, ELB/ALB/NLB, S3, CloudFront, Lambda, API Gateway, Elasticsearch
- **Multi-Region**: Automatically scans all AWS regions or specified regions
- **Advanced Logging**: Colorful console logs and detailed file logs with permission details
- **Error Handling**: Robust control of authentication and permission errors with detailed guidance
- **Reports**: Formatted table output and JSON files
- **Dockerized**: Easy deployment with Docker and Railway
- **Scheduled Scanning**: Configurable intervals (default: 12 hours)

## 📋 Detected Resources

### EC2 Instances
- Instances with public IP
- Security Groups with open ports (0.0.0.0/0)
- Instance state

### RDS Databases
- Databases with public access enabled
- Exposed endpoints and ports

### Load Balancers
- Classic Load Balancers with "internet-facing" scheme
- Public Application/Network Load Balancers
- Configured ports and protocols

### S3 Buckets
- Buckets with public ACL
- Buckets with policies allowing public access

### CloudFront Distributions
- Public content delivery networks
- Domain names and status

### Lambda Functions
- Functions with public URLs
- Function URL endpoints

### API Gateway
- Public REST APIs
- API endpoints and stages

### Elasticsearch Domains
- Public Elasticsearch clusters
- Domain endpoints with public access policies

## 🛠️ Installation and Usage

### Prerequisites
- Docker and Docker Compose
- AWS credentials with read permissions

### 1. Configure AWS Credentials

You have three options for authentication:

#### **Option A: AWS SSO (Recommended)**

```bash
# Run the SSO setup script
./setup_sso.sh
```

This will:
- Configure AWS SSO interactively
- Set up your profile
- Update the `.env` file automatically

#### **Option B: Manual SSO Setup**

```bash
# Configure SSO
aws configure sso

# Login to SSO
aws sso login --profile your-profile-name

# Update .env file
cp .env.example .env
# Edit .env and set: AWS_PROFILE=your-profile-name
```

#### **Option C: Direct Credentials**

```bash
cp .env.example .env
```

Edit `.env` with your credentials:

```bash
# For permanent credentials
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1

# For temporary credentials, also add:
AWS_SESSION_TOKEN=...
```

### 2. Run with Docker

```bash
# Build and run
docker-compose up --build

# Just run (if already built)
docker-compose up

# Run in background
docker-compose up -d
```

### 3. Run without Docker

```bash
# Install dependencies
pip install -r requirements.txt

# Run scanner
python main.py
```

## 📊 Program Output

### Console Logs
```
2024-01-20 10:30:15 - aws_public_scanner - INFO - ✅ Authenticated as: arn:aws:iam::123456789012:user/scanner
2024-01-20 10:30:16 - aws_public_scanner - INFO - 🚀 Starting AWS public resources scan
2024-01-20 10:30:17 - aws_public_scanner - INFO - 📍 Scanning 16 regions
2024-01-20 10:30:18 - aws_public_scanner - WARNING - 🌐 Public EC2 instance: i-1234567890abcdef0 (52.123.45.67) with ports: ['22/tcp', '80/tcp']
```

### Table Report
```
====================================================================================================
🌐 PUBLIC RESOURCES FOUND
====================================================================================================
┌─────────┬────────────┬──────────────────────────────┬─────────────┬─────────────────────────────┬──────────────┬─────────┐
│ Service │ Region     │ Resource ID                  │ Type        │ Public DNS                  │ Open Ports   │ State   │
├─────────┼────────────┼──────────────────────────────┼─────────────┼─────────────────────────────┼──────────────┼─────────┤
│ EC2     │ us-east-1  │ i-1234567890abcdef0          │ Instance    │ ec2-52-123-45-67.compute... │ 22/tcp, 80/tcp │ running │
│ RDS     │ us-west-2  │ my-public-database           │ Database    │ my-db.abc123.us-west-2.r... │ 3306         │ available │
└─────────┴────────────┴──────────────────────────────┴─────────────┴─────────────────────────────┴──────────────┴─────────┘
```

### JSON File
Reports are saved to `logs/public_resources_report_[timestamp].json`:

```json
{
  "scan_timestamp": 1705743025.123,
  "total_resources_scanned": 45,
  "public_resources_found": 2,
  "public_resources": [
    {
      "Service": "EC2",
      "Region": "us-east-1",
      "ResourceId": "i-1234567890abcdef0",
      "Type": "Instance",
      "PublicIP": "52.123.45.67",
      "PublicDNS": "ec2-52-123-45-67.compute-1.amazonaws.com",
      "OpenPorts": "22/tcp, 80/tcp",
      "State": "running"
    }
  ]
}
```

## 🔧 Advanced Configuration

### Environment Variables

| Variable | Description | Default Value |
|----------|-------------|---------------|
| `AWS_ACCESS_KEY_ID` | AWS Access Key | Required |
| `AWS_SECRET_ACCESS_KEY` | AWS Secret Key | Required |
| `AWS_DEFAULT_REGION` | Default region | `us-east-1` |
| `LOG_LEVEL` | Logging level | `INFO` |
| `LOG_FILE` | Log file | `logs/aws_public_resources.log` |
| `MAX_WORKERS` | Concurrent threads | `10` |
| `SERVICES_TO_SCAN` | Services to scan | `ec2,rds,elb,s3` |
| `TIMEOUT_SECONDS` | Operation timeout | `30` |

### Required IAM Permissions

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeRegions",
                "ec2:DescribeSecurityGroups",
                "rds:DescribeDBInstances",
                "elasticloadbalancing:DescribeLoadBalancers",
                "s3:ListAllMyBuckets",
                "s3:GetBucketAcl",
                "s3:GetBucketPolicy",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

## 🐳 Useful Docker Commands

```bash
# View logs in real time
docker-compose logs -f aws-public-scanner

# Run once
docker-compose run --rm aws-public-scanner

# Rebuild image
docker-compose build --no-cache

# Clean containers
docker-compose down --rmi all
```

## 🔍 Log Visualization

The project includes Dozzle for real-time log visualization:

1. Run: `docker-compose up -d`
2. Open: http://localhost:8080
3. Select the `aws-public-scanner` container

## ⚠️ Security Considerations

1. **Credentials**: Never commit the `.env` file with real credentials
2. **Minimal Permissions**: Use credentials with read-only permissions
3. **Logs**: Logs may contain sensitive information, protect them appropriately
4. **Network**: The scanner only requires internet access for AWS APIs

## 🤝 Contributing

1. Fork the project
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is under the MIT License. See `LICENSE` for more details.

## 🆘 Support

If you encounter any problems or have questions:

1. Check the logs for specific errors
2. Verify that AWS credentials are correct
3. Make sure you have the necessary IAM permissions
4. Open an issue on GitHub with problem details
