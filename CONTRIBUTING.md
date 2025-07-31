# Contributing to AWS Public Resources Scanner

Thank you for your interest in contributing to the AWS Public Resources Scanner! This document provides guidelines and information for contributors.

## 🤝 How to Contribute

### Reporting Issues

Before creating an issue, please:

1. **Search existing issues** to avoid duplicates
2. **Use a clear, descriptive title**
3. **Provide detailed information** including:
   - Steps to reproduce the issue
   - Expected vs actual behavior
   - Environment details (OS, Python version, AWS CLI version)
   - Log files or error messages
   - AWS services and regions affected

### Suggesting Enhancements

Enhancement suggestions are welcome! Please:

1. **Check if the enhancement already exists** in issues or discussions
2. **Clearly describe the enhancement** and its benefits
3. **Provide use cases** where this would be helpful
4. **Consider backwards compatibility**

### Code Contributions

#### Getting Started

1. **Fork the repository**
2. **Clone your fork**: `git clone https://github.com/YOUR_USERNAME/aws-public-resources-scanner.git`
3. **Create a feature branch**: `git checkout -b feature/your-feature-name`
4. **Set up development environment**:
   ```bash
   pip install -r requirements.txt
   cp .env.example .env
   # Configure your .env file
   ```

#### Development Guidelines

##### Code Style
- Follow **PEP 8** Python style guidelines
- Use **meaningful variable and function names**
- Add **docstrings** for all functions and classes
- Keep functions **small and focused**
- Use **type hints** where appropriate

##### Documentation
- Update **README.md** if adding new features
- Add **inline comments** for complex logic
- Update **docstrings** for any modified functions
- Include **examples** for new functionality

##### Testing
- Test your changes with **multiple AWS regions**
- Verify **error handling** works correctly
- Test with **different AWS services**
- Ensure **logging outputs** are appropriate
- Test **Docker container** functionality

##### Security
- **Never commit real AWS credentials**
- Use **minimal IAM permissions** for testing
- Be careful with **sensitive information** in logs
- Follow **AWS security best practices**

#### Code Structure

```
aws-public-resources-scanner/
├── main.py                 # Main scanner application
├── logger_config.py        # Logging configuration
├── requirements.txt        # Python dependencies
├── Dockerfile             # Docker container configuration
├── docker-compose.yml     # Docker Compose setup
├── .env.example          # Environment variables template
├── run_scanner.sh        # Execution script
└── README.md             # Project documentation
```

#### Adding New AWS Services

When adding support for new AWS services:

1. **Create a new method** in `AWSPublicResourceScanner` class:
   ```python
   def scan_service_name(self, region):
       """Scan SERVICE_NAME for public exposure"""
       try:
           # Implementation here
       except ClientError as e:
           # Handle AWS errors
       except Exception as e:
           # Handle other errors
   ```

2. **Add service to the service mapping** in `scan_region()` method
3. **Update documentation** with new service capabilities
4. **Add service to default SERVICES_TO_SCAN** if appropriate
5. **Test thoroughly** with the new service

#### Submitting Changes

1. **Commit your changes** with clear, descriptive messages:
   ```bash
   git commit -m "Add support for Lambda function scanning
   
   - Implement scan_lambda_functions method
   - Add public Lambda detection logic
   - Update documentation
   - Add error handling for Lambda permissions"
   ```

2. **Push to your fork**: `git push origin feature/your-feature-name`

3. **Create a Pull Request** with:
   - **Clear title** describing the change
   - **Detailed description** of what was changed and why
   - **Reference to related issues** if applicable
   - **Testing information** - how you tested the changes
   - **Screenshots** if applicable (for UI changes)

## 🔍 Development Tips

### Testing Locally

```bash
# Test with Docker
docker-compose up --build

# Test specific service
SERVICES_TO_SCAN=ec2 python main.py

# Test with different log levels
LOG_LEVEL=DEBUG python main.py
```

### Debugging

- Use **DEBUG log level** for detailed information
- Check **AWS CloudTrail** for API call details
- Verify **IAM permissions** if getting access errors
- Use **AWS CLI** to test permissions: `aws sts get-caller-identity`

### AWS Credentials for Testing

For development, create a dedicated IAM user with minimal permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:Describe*",
                "rds:Describe*",
                "elasticloadbalancing:Describe*",
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

## 📋 Pull Request Checklist

Before submitting a pull request, ensure:

- [ ] **Code follows project style** and conventions
- [ ] **All tests pass** and new functionality is tested
- [ ] **Documentation is updated** as needed
- [ ] **Commit messages are clear** and descriptive
- [ ] **No credentials or sensitive data** in commits
- [ ] **Docker container builds** successfully
- [ ] **README is updated** if adding new features
- [ ] **Error handling is appropriate**
- [ ] **Logging messages are helpful** and not excessive

## 🚀 Feature Roadmap

Areas where contributions are especially welcome:

### High Priority
- **Additional AWS services** (Lambda, API Gateway, CloudFront)
- **Performance optimizations** for large-scale scans
- **Better error recovery** and retry mechanisms
- **Enhanced reporting formats** (HTML, CSV, PDF)

### Medium Priority
- **Configuration file support** (YAML/JSON configs)
- **Webhook notifications** for found resources
- **Integration with security tools** (SIEM, ticketing)
- **Scheduling and automation** features

### Low Priority
- **Web UI** for easier management
- **Multi-account support** improvements
- **Custom rule engine** for resource detection
- **Historical tracking** of changes

## 🎯 Code Review Process

All contributions go through code review:

1. **Automated checks** run on all pull requests
2. **Maintainer review** for code quality and design
3. **Testing verification** in multiple environments
4. **Documentation review** for completeness
5. **Security review** for AWS best practices

## 📞 Getting Help

If you need help or have questions:

1. **Check existing documentation** first
2. **Search issues** for similar questions
3. **Create a new issue** with the "question" label
4. **Join discussions** for broader topics

## 🏆 Recognition

Contributors will be acknowledged in:
- **README.md** contributors section
- **Release notes** for significant contributions
- **GitHub contributors** page

Thank you for helping make AWS security scanning better for everyone! 🛡️
