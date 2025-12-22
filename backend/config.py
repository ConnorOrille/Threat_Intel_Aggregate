import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'postgresql://localhost/threat_intel')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key')
    
    # API Keys
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    OTX_API_KEY = os.getenv('OTX_API_KEY')