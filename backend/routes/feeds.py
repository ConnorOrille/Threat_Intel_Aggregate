from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required
from services.cisa_service import fetch_cisa_threats

bp = Blueprint('feeds', __name__, url_prefix='/api/feeds')

@bp.route('/fetch/cisa', methods=['POST'])
@jwt_required()
def fetch_cisa():
    """Manually trigger CISA feed fetch"""
    print("=== Fetching CISA threats ===")
    result = fetch_cisa_threats()
    
    if result['success']:
        return jsonify({
            'message': 'CISA threats fetched successfully',
            'added': result['added'],
            'total': result['total']
        })
    else:
        return jsonify({'error': result['error']}), 500

@bp.route('/sources', methods=['GET'])
@jwt_required()
def get_sources():
    """Get list of available threat feed sources"""
    sources = [
        {
            'id': 'cisa',
            'name': 'CISA Known Exploited Vulnerabilities',
            'description': 'Official US government list',
            'type': 'vulnerability',
            'requires_api_key': False
        }
    ]
    return jsonify({'sources': sources})