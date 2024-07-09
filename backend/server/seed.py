from app import app, db  # Import your Flask app instance and SQLAlchemy object
from models import User, RealEstate, Purchase, Review
from flask_bcrypt import Bcrypt
from datetime import datetime

bcrypt = Bcrypt(app)

def seed_data():
    try:
        # Clear existing data (if any)
        db.drop_all()
        db.create_all()

        # Seed users
        users = [
            User(name='Alice', email='alice@example.com', password=bcrypt.generate_password_hash('password1').decode('utf-8')),
            User(name='Bob', email='bob@example.com', password=bcrypt.generate_password_hash('password2').decode('utf-8')),
            User(name='Charlie', email='charlie@example.com', password=bcrypt.generate_password_hash('password3').decode('utf-8')),
            User(name='David', email='david@example.com', password=bcrypt.generate_password_hash('password4').decode('utf-8')),
            User(name='Eve', email='eve@example.com', password=bcrypt.generate_password_hash('password5').decode('utf-8'))
        ]
        db.session.add_all(users)
        db.session.commit()

        # Get user IDs after commits
        user_ids = [user.id for user in users]

        # Seed real estate listings
        real_estates = [
            RealEstate(title='Luxury Villa', price=1000000, address='123 Fancy St', description='A luxurious villa with modern amenities.', user_id=user_ids[0]),
            RealEstate(title='Cozy Cottage', price=200000, address='456 Cottage Rd', description='A small, cozy cottage perfect for a small family.', user_id=user_ids[1]),
            RealEstate(title='Modern Apartment', price=300000, address='789 Apartment Ln', description='A modern apartment in the heart of the city.', user_id=user_ids[2]),
            RealEstate(title='Seaside Retreat', price=500000, address='321 Beach Blvd', description='A beautiful retreat by the sea with stunning views.', user_id=user_ids[3]),
            RealEstate(title='Country Farmhouse', price=400000, address='567 Farm Rd', description='Charming farmhouse surrounded by nature.', user_id=user_ids[4])
        ]
        db.session.add_all(real_estates)
        db.session.commit()

        # Seed reviews
        reviews = [
            Review(user_id=user_ids[0], real_estate_id=1, rating=5, comment='Absolutely loved it!'),
            Review(user_id=user_ids[1], real_estate_id=2, rating=4, comment='Very nice and cozy.'),
            Review(user_id=user_ids[2], real_estate_id=3, rating=3, comment='Good, but could be better.'),
            Review(user_id=user_ids[3], real_estate_id=4, rating=5, comment='Incredible views and peaceful surroundings.'),
            Review(user_id=user_ids[4], real_estate_id=5, rating=4, comment='Perfect for a quiet getaway.')
        ]
        db.session.add_all(reviews)
        db.session.commit()

        # Seed purchases
        purchases = [
            Purchase(user_id=user_ids[0], real_estate_id=1, date=datetime.utcnow()),
            Purchase(user_id=user_ids[1], real_estate_id=2, date=datetime.utcnow()),
            Purchase(user_id=user_ids[2], real_estate_id=3, date=datetime.utcnow()),
            Purchase(user_id=user_ids[3], real_estate_id=4, date=datetime.utcnow()),
            Purchase(user_id=user_ids[4], real_estate_id=5, date=datetime.utcnow())
        ]
        db.session.add_all(purchases)
        db.session.commit()

        print("Database seeded successfully!")

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        db.session.rollback()

if __name__ == '__main__':
    with app.app_context():
        seed_data()
