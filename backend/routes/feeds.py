from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required
from services.cisa_service import fetch_cisa_threats
from services.abuseipdb_service import fetch_abuseipdb_threats
from services.urlhaus_service import fetch_urlhaus_threats

bp = Blueprint('feeds', __name__, url_prefix='/api/feeds')

@bp.route('/fetch/cisa', methods=['POST'])
@jwt_required()
def fetch_cisa():
    """Manually trigger CISA feed fetch"""
    result = fetch_cisa_threats()
    
    if result['success']:
        return jsonify({
            'message': 'CISA threats fetched successfully',
            'added': result['added'],
            'total': result['total']
        })
    else:
        return jsonify({'error': result['error']}), 500


@bp.route('/fetch/abuseipdb', methods=['POST'])
@jwt_required()
def fetch_abuseipdb():
    """Manually trigger AbuseIPDB feed fetch"""
    result = fetch_abuseipdb_threats()
    
    if result['success']:
        return jsonify({
            'message': 'AbuseIPDB threats fetched successfully',
            'added': result['added'],
            'total': result['total']
        })
    else:
        return jsonify({'error': result['error']}), 500


@bp.route('/fetch/urlhaus', methods=['POST'])
@jwt_required()
def fetch_urlhaus():
    """Manually trigger URLhaus feed fetch"""
    result = fetch_urlhaus_threats()
    
    if result['success']:
        return jsonify({
            'message': 'URLhaus threats fetched successfully',
            'added': result['added'],
            'total': result['total']
        })
    else:
        return jsonify({'error': result['error']}), 500


@bp.route('/fetch/all', methods=['POST'])
@jwt_required()
def fetch_all():
    """Fetch from all threat feeds"""
    results = {
        'cisa': fetch_cisa_threats(),
        'abuseipdb': fetch_abuseipdb_threats(),
        'urlhaus': fetch_urlhaus_threats()
    }
    
    total_added = sum(r.get('added', 0) for r in results.values() if r['success'])
    
    return jsonify({
        'message': f'Fetched threats from all sources. Added {total_added} new threats.',
        'results': results
    })


@bp.route('/sources', methods=['GET'])
@jwt_required()
def get_sources():
    """Get list of available threat feed sources"""
    sources = [
        {
            'id': 'cisa',
            'name': 'CISA Known Exploited Vulnerabilities',
            'description': 'Official US government list of actively exploited vulnerabilities',
            'type': 'vulnerability',
            'requires_api_key': False
        },
        {
            'id': 'abuseipdb',
            'name': 'AbuseIPDB',
            'description': 'Database of malicious IP addresses',
            'type': 'malicious_ip',
            'requires_api_key': True
        },
        {
            'id': 'urlhaus',
            'name': 'URLhaus (Abuse.ch)',
            'description': 'Malware distribution URLs',
            'type': 'malware_url',
            'requires_api_key': False
        }
    ]
    
    return jsonify({'sources': sources})