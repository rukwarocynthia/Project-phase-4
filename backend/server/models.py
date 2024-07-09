from flask_sqlalchemy import SQLAlchemy
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.orm import validates
from datetime import datetime

db = SQLAlchemy()

class User(db.Model, SerializerMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    reviews = db.relationship('Review', back_populates='user', lazy=True)
    purchases = db.relationship('Purchase', back_populates='user', lazy=True)
    real_estates = db.relationship('RealEstate', back_populates='user', lazy=True)

    @validates('email')
    def validate_email(self, key, email):
        assert '@' in email, 'Invalid email address'
        return email

class RealEstate(db.Model, SerializerMixin):
    __tablename__ = 'real_estate'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    address = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(100), nullable=False)

    reviews = db.relationship('Review', back_populates='real_estate', lazy=True)
    purchases = db.relationship('Purchase', back_populates='real_estate', lazy=True)
    user = db.relationship('User', back_populates='real_estates')

class Purchase(db.Model, SerializerMixin):
    __tablename__ = 'purchase'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    real_estate_id = db.Column(db.Integer, db.ForeignKey('real_estate.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('User', back_populates='purchases')
    real_estate = db.relationship('RealEstate', back_populates='purchases')

class Review(db.Model, SerializerMixin):
    __tablename__ = 'review'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    real_estate_id = db.Column(db.Integer, db.ForeignKey('real_estate.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=False)

    user = db.relationship('User', back_populates='reviews')
    real_estate = db.relationship('RealEstate', back_populates='reviews')
