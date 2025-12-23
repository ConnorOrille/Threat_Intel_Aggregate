import requests
from datetime import datetime
from models import db, Threat

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_cisa_threats():
    """Fetch CISA Known Exploited Vulnerabilities"""
    try:
        print("Fetching from CISA...")
        response = requests.get(CISA_KEV_URL, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        vulnerabilities = data.get('vulnerabilities', [])
        added_count = 0
        
        print(f"Processing {len(vulnerabilities)} vulnerabilities...")
        
        for vuln in vulnerabilities:
            existing = Threat.query.filter_by(threat_id=vuln['cveID']).first()
            
            if not existing:
                threat = Threat(
                    threat_id=vuln['cveID'],
                    source='CISA',
                    threat_type='vulnerability',
                    title=vuln.get('vulnerabilityName', 'Unknown'),
                    description=vuln.get('shortDescription', ''),
                    severity='critical',
                    indicators={
                        'vendor': vuln.get('vendorProject', ''),
                        'product': vuln.get('product', ''),
                        'cve_id': vuln['cveID']
                    },
                    threat_metadata={
                        'required_action': vuln.get('requiredAction', ''),
                        'due_date': vuln.get('dueDate', ''),
                        'known_ransomware': vuln.get('knownRansomwareCampaignUse', 'Unknown')
                    },
                    date_discovered=datetime.strptime(vuln['dateAdded'], '%Y-%m-%d') if vuln.get('dateAdded') else None
                )
                db.session.add(threat)
                added_count += 1
        
        db.session.commit()
        print(f"Added {added_count} threats")
        return {'success': True, 'added': added_count, 'total': len(vulnerabilities)}
        
    except Exception as e:
        db.session.rollback()
        print(f"Error: {str(e)}")
        return {'success': False, 'error': str(e)}