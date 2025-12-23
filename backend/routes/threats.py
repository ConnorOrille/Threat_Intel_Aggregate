from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy import or_, and_
from models import db, Threat, Bookmark, User
from datetime import datetime, timedelta

bp = Blueprint('threats', __name__, url_prefix='/api/threats')

@bp.route('/', methods=['GET'])
@jwt_required()
@bp.route('/', methods=['GET'])
@jwt_required()
def get_threats():
    """Get all threats with optional filtering"""
    try:
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        source = request.args.get('source')
        threat_type = request.args.get('type')
        severity = request.args.get('severity')
        search = request.args.get('search')
        days = request.args.get('days', type=int)
        
        # Start with base query
        query = Threat.query.filter_by(is_active=True)
        
        # Apply filters
        if source:
            query = query.filter_by(source=source)
        
        if threat_type:
            query = query.filter_by(threat_type=threat_type)
        
        if severity:
            query = query.filter_by(severity=severity)
        
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    Threat.title.ilike(search_term),
                    Threat.description.ilike(search_term),
                    Threat.threat_id.ilike(search_term)
                )
            )
        
        if days:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            query = query.filter(Threat.date_discovered >= cutoff_date)
        
        # Order by most recent first
        query = query.order_by(Threat.date_discovered.desc())
        
        # Paginate results
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
        # Convert to dict - with error handling for each threat
        threats = []
        for threat in pagination.items:
            try:
                threats.append(threat.to_dict())
            except Exception as e:
                print(f"Error converting threat {threat.id}: {str(e)}")  # Debug print
                continue  # Skip this threat and continue
        
        return jsonify({
            'threats': threats,
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': page,
            'per_page': per_page
        })
    
    except Exception as e:
        print(f"Error in get_threats: {str(e)}")  # Debug print
        import traceback
        traceback.print_exc()  # Print full stack trace
        return jsonify({'error': str(e)}), 500


@bp.route('/<int:threat_id>', methods=['GET'])
@jwt_required()
def get_threat(threat_id):
    """Get a single threat by ID"""
    threat = Threat.query.get(threat_id)
    
    if not threat:
        return jsonify({'error': 'Threat not found'}), 404
    
    # Check if current user has bookmarked this threat
    user_id = get_jwt_identity()
    bookmark = Bookmark.query.filter_by(user_id=user_id, threat_id=threat_id).first()
    
    threat_data = threat.to_dict()
    threat_data['is_bookmarked'] = bookmark is not None
    threat_data['bookmark_notes'] = bookmark.notes if bookmark else None
    
    return jsonify(threat_data)


@bp.route('/stats', methods=['GET'])
@jwt_required()
def get_stats():
    """Get statistics about threats"""
    try:
        total_threats = Threat.query.filter_by(is_active=True).count()
        
        # Count by source
        sources = db.session.query(
            Threat.source,
            db.func.count(Threat.id)
        ).filter_by(is_active=True).group_by(Threat.source).all()
        
        # Count by severity
        severities = db.session.query(
            Threat.severity,
            db.func.count(Threat.id)
        ).filter_by(is_active=True).group_by(Threat.severity).all()
        
        # Count by type
        types = db.session.query(
            Threat.threat_type,
            db.func.count(Threat.id)
        ).filter_by(is_active=True).group_by(Threat.threat_type).all()
        
        # Recent threats (last 7 days)
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        recent_count = Threat.query.filter(
            and_(
                Threat.is_active == True,
                Threat.date_discovered >= seven_days_ago
            )
        ).count()
        
        # Threats per day for last 30 days
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        daily_threats = db.session.query(
            db.func.date(Threat.date_discovered).label('date'),
            db.func.count(Threat.id).label('count')
        ).filter(
            and_(
                Threat.is_active == True,
                Threat.date_discovered >= thirty_days_ago
            )
        ).group_by(db.func.date(Threat.date_discovered)).all()
        
        return jsonify({
            'total_threats': total_threats,
            'recent_threats_7d': recent_count,
            'by_source': {source: count for source, count in sources},
            'by_severity': {severity: count for severity, count in severities},
            'by_type': {threat_type: count for threat_type, count in types},
            'daily_trends': [
                {'date': str(date), 'count': count} 
                for date, count in daily_threats
            ]
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/bookmarks', methods=['GET'])
@jwt_required()
def get_bookmarks():
    """Get all bookmarked threats for current user"""
    user_id = get_jwt_identity()
    
    bookmarks = Bookmark.query.filter_by(user_id=user_id).all()
    
    result = []
    for bookmark in bookmarks:
        threat_data = bookmark.threat.to_dict()
        threat_data['bookmark_notes'] = bookmark.notes
        threat_data['bookmarked_at'] = bookmark.created_at.isoformat()
        result.append(threat_data)
    
    return jsonify({'bookmarks': result, 'total': len(result)})


@bp.route('/<int:threat_id>/bookmark', methods=['POST'])
@jwt_required()
def bookmark_threat(threat_id):
    """Bookmark a threat"""
    user_id = get_jwt_identity()
    
    # Check if threat exists
    threat = Threat.query.get(threat_id)
    if not threat:
        return jsonify({'error': 'Threat not found'}), 404
    
    # Check if already bookmarked
    existing = Bookmark.query.filter_by(user_id=user_id, threat_id=threat_id).first()
    if existing:
        return jsonify({'error': 'Already bookmarked'}), 400
    
    data = request.get_json() or {}
    notes = data.get('notes', '')
    
    bookmark = Bookmark(
        user_id=user_id,
        threat_id=threat_id,
        notes=notes
    )
    
    db.session.add(bookmark)
    db.session.commit()
    
    return jsonify({
        'message': 'Threat bookmarked successfully',
        'bookmark': bookmark.to_dict()
    }), 201


@bp.route('/<int:threat_id>/bookmark', methods=['PUT'])
@jwt_required()
def update_bookmark(threat_id):
    """Update bookmark notes"""
    user_id = get_jwt_identity()
    
    bookmark = Bookmark.query.filter_by(user_id=user_id, threat_id=threat_id).first()
    if not bookmark:
        return jsonify({'error': 'Bookmark not found'}), 404
    
    data = request.get_json()
    if 'notes' in data:
        bookmark.notes = data['notes']
    
    db.session.commit()
    
    return jsonify({
        'message': 'Bookmark updated successfully',
        'bookmark': bookmark.to_dict()
    })


@bp.route('/<int:threat_id>/bookmark', methods=['DELETE'])
@jwt_required()
def unbookmark_threat(threat_id):
    """Remove a bookmark"""
    user_id = get_jwt_identity()
    
    bookmark = Bookmark.query.filter_by(user_id=user_id, threat_id=threat_id).first()
    if not bookmark:
        return jsonify({'error': 'Bookmark not found'}), 404
    
    db.session.delete(bookmark)
    db.session.commit()
    
    return jsonify({'message': 'Bookmark removed successfully'})


@bp.route('/search', methods=['POST'])
@jwt_required()
def advanced_search():
    """Advanced search with multiple criteria"""
    try:
        data = request.get_json()
        
        query = Threat.query.filter_by(is_active=True)
        
        # Search term
        if data.get('search'):
            search_term = f"%{data['search']}%"
            query = query.filter(
                or_(
                    Threat.title.ilike(search_term),
                    Threat.description.ilike(search_term),
                    Threat.threat_id.ilike(search_term)
                )
            )
        
        # Multiple sources
        if data.get('sources'):
            query = query.filter(Threat.source.in_(data['sources']))
        
        # Multiple severities
        if data.get('severities'):
            query = query.filter(Threat.severity.in_(data['severities']))
        
        # Multiple types
        if data.get('types'):
            query = query.filter(Threat.threat_type.in_(data['types']))
        
        # Date range
        if data.get('start_date'):
            start = datetime.fromisoformat(data['start_date'])
            query = query.filter(Threat.date_discovered >= start)
        
        if data.get('end_date'):
            end = datetime.fromisoformat(data['end_date'])
            query = query.filter(Threat.date_discovered <= end)
        
        # Confidence score range
        if data.get('min_confidence'):
            query = query.filter(Threat.confidence_score >= data['min_confidence'])
        
        # Sort
        sort_by = data.get('sort_by', 'date_discovered')
        sort_order = data.get('sort_order', 'desc')
        
        if hasattr(Threat, sort_by):
            sort_column = getattr(Threat, sort_by)
            if sort_order == 'asc':
                query = query.order_by(sort_column.asc())
            else:
                query = query.order_by(sort_column.desc())
        
        # Pagination
        page = data.get('page', 1)
        per_page = data.get('per_page', 20)
        
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
        threats = [threat.to_dict() for threat in pagination.items]
        
        return jsonify({
            'threats': threats,
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': page
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500