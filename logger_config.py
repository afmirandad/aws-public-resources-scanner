import logging
import colorlog
import os
from datetime import datetime


class AWSLogger:
    def __init__(self, log_file=None, log_level='INFO'):
        self.logger = logging.getLogger('aws_public_scanner')
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Console handler with colors
        console_handler = colorlog.StreamHandler()
        console_formatter = colorlog.ColoredFormatter(
            '%(log_color)s%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            }
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler
        if log_file:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
    
    def get_logger(self):
        return self.logger
    
    def log_service_start(self, service_name, region):
        self.logger.info(f"🔍 Starting scan of {service_name} in region {region}")
    
    def log_service_complete(self, service_name, region, resource_count):
        self.logger.info(f"✅ Completed scan of {service_name} in {region}: {resource_count} resources found")
    
    def log_service_error(self, service_name, region, error):
        self.logger.error(f"❌ Error scanning {service_name} in {region}: {str(error)}")
    
    def log_auth_error(self, service_name, error):
        self.logger.error(f"🔒 Authentication error in {service_name}: {str(error)}")
    
    def log_permission_error(self, service_name, error):
        self.logger.warning(f"⚠️ No permissions for {service_name}: {str(error)}")
    
    def log_public_resource(self, service_name, resource_id, resource_type, details):
        self.logger.warning(f"🌐 PUBLIC RESOURCE found - {service_name}: {resource_type} {resource_id} - {details}")
    
    def log_scan_summary(self, total_resources, public_resources, scan_time):
        self.logger.info(f"📊 SUMMARY: {total_resources} resources scanned, {public_resources} public, time: {scan_time:.2f}s")
