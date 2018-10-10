from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

db = SQLAlchemy()
bcrypt = Bcrypt()

def connect_db(app):
    db.app = app
    db.init_app(app)

class User(db.Model):
    """Model to store user details"""

    __tablename__ = 'users'

    username = db.Column(db.Text, primary_key=True)
    password = db.Column(db.Text, nullable=False)
    email = db.Column(db.Text, nullable=False, unique=True)
    first_name = db.Column(db.Text, nullable=False)
    last_name = db.Column(db.Text, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    feedback = db.relationship('Feedback',
                            backref='users')

    @property
    def full_name(self):
        """Return full name of user."""

        return f"{self.first_name} {self.last_name}"

    @classmethod
    def register(cls, username, password, email, first_name, last_name):
        """Register a user, hashing thier password"""

        hashed = bcrypt.generate_password_hash(password)
        hashed_utf8 = hashed.decode('utf8')

        return cls(username=username.lower(), password=hashed_utf8, email=email, first_name=first_name, last_name=last_name)
   
    @classmethod
    def authenticate(cls, username, password):
        """Login a user, authenticating their password"""

        user = User.query.filter_by(username = username.lower()).one_or_none()
        if user:
            if bcrypt.check_password_hash(user.password, password):
                return user
        # nice todo: differentiate between wrong pass and wrong username
        return False
            
class Feedback(db.Model):
    """Model for user feedback"""

    __tablename__ = 'feedback'

    id = db.Column(db.Integer, 
                    primary_key=True, 
                    autoincrement=True)
    title = db.Column(db.Text, nullable=False)
    content = db.Column(db.Text, nullable=False)
    username = db.Column(db.Text, 
                        db.ForeignKey('users.username'), 
                        nullable=False)