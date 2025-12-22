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
    JWTManager(app)
    
    # Import and register blueprints
    from routes import auth, threats, feeds
    app.register_blueprint(auth.bp)
    app.register_blueprint(threats.bp)
    app.register_blueprint(feeds.bp)
    
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