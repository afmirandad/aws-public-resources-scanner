# Security Policy

## Supported Versions

We actively maintain and provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of AWS Public Resources Scanner seriously. If you discover a security vulnerability, please follow these guidelines:

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please email security details to: **[your-email@domain.com]**

Include the following information:
- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Any suggested fixes or mitigations

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your report within 48 hours
- **Initial Assessment**: We will provide an initial assessment within 5 business days
- **Updates**: We will keep you informed of our progress
- **Resolution**: We aim to resolve critical vulnerabilities within 30 days

### Responsible Disclosure

We follow responsible disclosure practices:

1. **Investigation**: We investigate and validate the reported vulnerability
2. **Fix Development**: We develop and test a fix
3. **Release**: We release the fix in a new version
4. **Public Disclosure**: We publicly disclose the vulnerability after a fix is available

## Security Considerations

### AWS Credentials
- **Never commit** AWS credentials to the repository
- Use **IAM roles** when possible instead of access keys
- Follow the **principle of least privilege**
- Regularly **rotate access keys**

### Container Security
- The Docker container runs with **non-root user** when possible
- **No sensitive data** is stored in the container image
- Use **official base images** for better security

### Data Handling
- Scanner **only reads** AWS resource metadata
- **No sensitive data** is logged or stored permanently
- Reports may contain **resource identifiers** - secure them appropriately

### Network Security
- Scanner only requires **outbound HTTPS** to AWS APIs
- **No inbound connections** required
- Can run in **isolated networks** with AWS API access

## Security Best Practices for Users

### IAM Permissions
Use minimal IAM permissions for scanning:

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

### Environment Security
- Use **dedicated AWS accounts** for security scanning when possible
- **Secure the .env file** with appropriate file permissions
- **Monitor scanner usage** through AWS CloudTrail
- **Regularly review** IAM permissions and access patterns

### Report Security
- **Encrypt sensitive reports** if storing long-term
- **Limit access** to scan results
- **Securely dispose** of reports when no longer needed
- **Sanitize logs** before sharing

## Known Security Considerations

### False Positives
- Scanner may report **intentionally public resources**
- **Review all findings** before taking action
- **Understand your architecture** before making changes

### Rate Limiting
- AWS APIs have **rate limits** that may affect scanning
- Scanner implements **reasonable delays** but may still hit limits
- **Large-scale scanning** should be performed during off-peak hours

### Permissions
- **Insufficient permissions** may result in incomplete scans
- **Overly broad permissions** may violate security policies
- **Balance security and functionality** when configuring IAM

## Updates and Patches

### Security Updates
- **Critical vulnerabilities** are addressed immediately
- **Security patches** are released as soon as possible
- **Users are notified** through GitHub releases and security advisories

### Staying Updated
- **Watch the repository** for security announcements
- **Subscribe to releases** to be notified of updates
- **Regularly update** to the latest version

## Contact Information

For security-related questions or concerns:

- **Email**: [your-email@domain.com]
- **GPG Key**: [Optional: include GPG key fingerprint]

For general questions and support, please use GitHub Issues.

---

**Note**: This security policy may be updated periodically. Please check back regularly for the most current information.
