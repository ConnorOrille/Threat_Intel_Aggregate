import requests
from datetime import datetime
from models import db, Threat

URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

def fetch_urlhaus_threats():
    """Fetch malicious URLs from URLhaus"""
    
    try:
        response = requests.post(URLHAUS_API_URL, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        if data['query_status'] != 'ok':
            return {'success': False, 'error': 'URLhaus API returned error'}
        
        urls = data.get('urls', [])
        added_count = 0
        
        for url_data in urls:
            threat_id = f"URL-{url_data['id']}"
            
            # Check if already exists
            existing = Threat.query.filter_by(threat_id=threat_id).first()
            
            if not existing:
                threat = Threat(
                    threat_id=threat_id,
                    source='URLhaus',
                    threat_type='malware_url',
                    title=f"Malware URL: {url_data.get('url_status', 'Unknown')}",
                    description=url_data.get('url', '')[:500],  # Truncate long URLs
                    severity=_get_severity_from_threat(url_data.get('threat', '')),
                    indicators={
                        'url': url_data.get('url', ''),
                        'host': url_data.get('host', ''),
                        'url_status': url_data.get('url_status', '')
                    },
                    metadata={
                        'threat_type': url_data.get('threat', ''),
                        'tags': url_data.get('tags', []),
                        'reporter': url_data.get('reporter', 'Unknown'),
                        'larted': url_data.get('larted', False)
                    },
                    date_discovered=datetime.fromisoformat(url_data['dateadded'].replace(' ', 'T'))
                )
                db.session.add(threat)
                added_count += 1
        
        db.session.commit()
        return {'success': True, 'added': added_count, 'total': len(urls)}
    
    except Exception as e:
        db.session.rollback()
        return {'success': False, 'error': str(e)}


def _get_severity_from_threat(threat_type):
    """Convert threat type to severity level"""
    high_severity = ['ransomware', 'banking_trojan', 'backdoor']
    medium_severity = ['trojan', 'malware_download']
    
    threat_lower = threat_type.lower()
    
    if any(hs in threat_lower for hs in high_severity):
        return 'high'
    elif any(ms in threat_lower for ms in medium_severity):
        return 'medium'
    else:
        return 'low'