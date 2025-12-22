from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    bookmarks = db.relationship('Bookmark', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'created_at': self.created_at.isoformat()
        }

class Threat(db.Model):
    __tablename__ = 'threats'
    
    id = db.Column(db.Integer, primary_key=True)
    threat_id = db.Column(db.String(255), unique=True)
    source = db.Column(db.String(50), nullable=False)
    threat_type = db.Column(db.String(50))
    title = db.Column(db.Text)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20))
    confidence_score = db.Column(db.Integer)
    indicators = db.Column(db.JSON)
    metadata = db.Column(db.JSON)
    date_discovered = db.Column(db.DateTime)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    bookmarks = db.relationship('Bookmark', backref='threat', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'threat_id': self.threat_id,
            'source': self.source,
            'threat_type': self.threat_type,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'confidence_score': self.confidence_score,
            'indicators': self.indicators,
            'metadata': self.metadata,
            'date_discovered': self.date_discovered.isoformat() if self.date_discovered else None,
            'date_added': self.date_added.isoformat(),
            'is_active': self.is_active
        }

class Bookmark(db.Model):
    __tablename__ = 'bookmarks'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    threat_id = db.Column(db.Integer, db.ForeignKey('threats.id'), nullable=False)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'threat_id'),)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'threat_id': self.threat_id,
            'notes': self.notes,
            'created_at': self.created_at.isoformat()
        }