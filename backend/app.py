from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from config import Config
from models import db

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize extensions
    db.init_app(app)
    CORS(app)
    jwt = JWTManager(app)
    
    # Add JWT error handlers - ADD THESE
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({
            'error': 'Token has expired',
            'message': 'Please log in again'
        }), 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({
            'error': 'Invalid token',
            'message': str(error)
        }), 422
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({
            'error': 'No token provided',
            'message': 'Authorization header is missing'
        }), 401
    
    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return jsonify({
            'error': 'Token has been revoked',
            'message': 'Please log in again'
        }), 401
    
    # Import blueprints
    from routes.auth import bp as auth_bp
    from routes.threats import bp as threats_bp
    from routes.feeds import bp as feeds_bp
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(threats_bp)
    app.register_blueprint(feeds_bp)
    
    # Create tables
    with app.app_context():
        db.create_all()
    
    @app.route('/')
    def index():
        return jsonify({
            'message': 'Threat Intelligence API',
            'version': '1.0',
            'endpoints': {
                'auth': '/api/auth',
                'threats': '/api/threats',
                'feeds': '/api/feeds'
            }
        })
    
    @app.route('/health')
    def health():
        return jsonify({'status': 'healthy'})
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=5000)