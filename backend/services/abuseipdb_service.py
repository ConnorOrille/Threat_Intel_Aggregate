import requests
from datetime import datetime
from models import db, Threat
from config import Config

ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/blacklist"

def fetch_abuseipdb_threats():
    """Fetch malicious IPs from AbuseIPDB"""
    
    if not Config.ABUSEIPDB_API_KEY:
        return {'success': False, 'error': 'AbuseIPDB API key not configured'}
    
    try:
        headers = {
            'Key': Config.ABUSEIPDB_API_KEY,
            'Accept': 'application/json'
        }
        
        params = {
            'confidenceMinimum': 90,  # Only IPs with 90%+ confidence
            'limit': 100
        }
        
        response = requests.get(ABUSEIPDB_API_URL, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        if 'data' not in data:
            return {'success': False, 'error': 'Invalid API response'}
        
        ips = data['data']
        added_count = 0
        
        for ip_data in ips:
            threat_id = f"IP-{ip_data['ipAddress']}"
            
            # Check if already exists
            existing = Threat.query.filter_by(threat_id=threat_id).first()
            
            if not existing:
                threat = Threat(
                    threat_id=threat_id,
                    source='AbuseIPDB',
                    threat_type='malicious_ip',
                    title=f"Malicious IP: {ip_data['ipAddress']}",
                    description=f"Reported {ip_data['totalReports']} times",
                    severity=_get_severity_from_confidence(ip_data['abuseConfidenceScore']),
                    confidence_score=ip_data['abuseConfidenceScore'],
                    indicators={
                        'ip_address': ip_data['ipAddress'],
                        'country_code': ip_data.get('countryCode', 'Unknown'),
                        'isp': ip_data.get('isp', 'Unknown')
                    },
                    metadata={
                        'total_reports': ip_data['totalReports'],
                        'num_distinct_users': ip_data.get('numDistinctUsers', 0),
                        'usage_type': ip_data.get('usageType', 'Unknown'),
                        'domain': ip_data.get('domain', '')
                    },
                    date_discovered=datetime.fromisoformat(ip_data['lastReportedAt'].replace('Z', '+00:00'))
                )
                db.session.add(threat)
                added_count += 1
        
        db.session.commit()
        return {'success': True, 'added': added_count, 'total': len(ips)}
    
    except Exception as e:
        db.session.rollback()
        return {'success': False, 'error': str(e)}


def _get_severity_from_confidence(confidence):
    """Convert confidence score to severity level"""
    if confidence >= 90:
        return 'critical'
    elif confidence >= 75:
        return 'high'
    elif confidence >= 50:
        return 'medium'
    else:
        return 'low'