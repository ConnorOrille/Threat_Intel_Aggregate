from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from config import Config
from models import db

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Print config for debugging
    print(f"JWT_SECRET_KEY configured: {app.config.get('JWT_SECRET_KEY') is not None}")
    
    # Initialize extensions
    db.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    jwt = JWTManager(app)
    
    # JWT error handlers
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({'error': 'Token expired'}), 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({'error': 'Invalid token', 'message': str(error)}), 422
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({'error': 'No token', 'message': str(error)}), 401
    
    # Create tables first
    with app.app_context():
        db.create_all()
    
    # Then import and register blueprints
    from routes.auth import bp as auth_bp
    from routes.threats import bp as threats_bp
    from routes.feeds import bp as feeds_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(threats_bp)
    app.register_blueprint(feeds_bp)
    
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