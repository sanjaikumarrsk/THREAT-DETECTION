"""
Configuration settings for Cyber Threat Defense System
"""
import os
from datetime import timedelta

class Settings:
    """Application settings"""
    
    # Flask
    DEBUG = os.getenv('FLASK_DEBUG', 'False') == 'True'
    TESTING = os.getenv('FLASK_TESTING', 'False') == 'True'
    
    # Security
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key-change-in-production')
    JWT_ALGORITHM = 'HS256'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'DATABASE_URL',
        'postgresql://user:password@localhost:5432/cyber_threat_db'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Redis Cache
    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    CACHE_TYPE = 'redis'
    CACHE_REDIS_URL = REDIS_URL
    CACHE_DEFAULT_TIMEOUT = 300
    
    # Security Settings
    DATA_ENCRYPTION_ENABLED = os.getenv('DATA_ENCRYPTION_ENABLED', 'True') == 'True'
    LOCAL_DATA_VAULT_ONLY = os.getenv('LOCAL_DATA_VAULT_ONLY', 'True') == 'True'
    ENABLE_AUDIT_LOGGING = os.getenv('ENABLE_AUDIT_LOGGING', 'True') == 'True'
    
    # Authorization & Defense
    DEFAULT_AUTHORIZATION_TIMEOUT = 600  # seconds
    CRITICAL_THREAT_TIMEOUT = 120  # seconds
    HIGH_THREAT_TIMEOUT = 300  # seconds
    DEFAULT_FAIL_SAFE_ACTION = 'PAUSE'
    
    # Data Retention
    TELEMETRY_RETENTION_DAYS = 30
    ALERT_RETENTION_DAYS = 90
    AUDIT_LOG_RETENTION_DAYS = 365
    
    # API
    API_TITLE = "Cyber Threat Defense System API"
    API_VERSION = "1.0.0"
    OPENAPI_VERSION = "3.0.2"
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', 'logs/application.log')
    
    # Features
    ENABLE_COLLECTIVE_INTELLIGENCE = True
    ENABLE_FEDERATED_LEARNING = False  # Not enabled in MVP
    ENABLE_PATTERN_SHARING = True
    
    # Certification
    CERTIFICATION_READY = True
    CERTIFIED = False  # Only set to True when actual certification obtained
    CERTIFICATION_ROADMAP = [
        'Security Testing',
        'Vulnerability Assessment',
        'Penetration Testing',
        'Independent Audit'
    ]

settings = Settings()
