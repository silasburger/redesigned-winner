from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, BooleanField, PasswordField
from wtforms.fields.html5 import EmailField
from wtforms.validators import InputRequired, DataRequired, Optional, Email

class RegisterForm(FlaskForm):
    """Form class to show new customer a register form"""

    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    email = EmailField('Email', validators=[InputRequired(), Email()])
    first_name = StringField('First Name', validators=[InputRequired()])
    last_name = StringField('Last Name', validators=[InputRequired()])

class LoginForm(FlaskForm):
    """Form class to login user"""

    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    
class FeedbackForm(FlaskForm):
    """Form class to show logged in user a feedback form"""

    title = StringField('Title', validators=[InputRequired()])
    content = TextAreaField('Content', validators=[InputRequired()])
