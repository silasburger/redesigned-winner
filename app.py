# FLASK FEEDBACK PROJECT

from flask import Flask, request, redirect, render_template, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError
from models import db, connect_db, User, Feedback
from formclasses import RegisterForm, LoginForm, FeedbackForm
from secret import SECRET_KEY
from werkzeug.exceptions import Unauthorized

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///flask-feedback-db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True

connect_db(app)
db.create_all()

app.config['SECRET_KEY'] = SECRET_KEY
debug = DebugToolbarExtension(app)

# HELPER FUNCTIONS

def check_authorization(username):
    if "username" not in session:
        flash('You are not authorized')
        return False
    else:
        #check if user has access

        if username == session.get("username") or User.query.get(session.get("username")).is_admin:
            return User.query.get_or_404(username)
        else:
            return False

# REDIRECT TO REGISTER PAGE

@app.route('/')
def redirect_to_register():
    """Redirect user to /register"""

    return redirect('/register')

@app.route('/404')
def show_error_page():
    """Show 404 error page"""

    return render_template('404.html')

@app.route('/register', methods=['POST', 'GET'])
def submit_register_form_data():
    """Submit"""

    if session.get("username"):
        username = session.get("username")
        return redirect(f'/users/{username}')

    form = RegisterForm()

    if form.validate_on_submit():
        username = form.data['username']
        password = form.data['password']
        email = form.data['email']
        first_name = form.data['first_name']
        last_name = form.data['last_name']

        try:
            user = User.register(username, password, email, first_name, last_name)
            db.session.add(user)
            db.session.commit()
        except IntegrityError:
            form.username.errors.append('Username is already taken!')
            return render_template('/register_form.html', form=form)

        return redirect(f'/users/{username}')
    else:
        return render_template('/register_form.html', form=form)

@app.route('/users/<username>')
def show_user_details(username):
    """Show user details for logged in user"""

    user = check_authorization(username)

    if not user:
        return redirect('/404')

    feedback = user.feedback

    return render_template('user_details.html', user=user, feedback=feedback)

@app.route('/login', methods=['GET', 'POST'])
def handle_login():
    """Display and process login form"""
    
    if session.get("username"):
        username = session.get("username")
        return redirect(f'/users/{username}')

    form = LoginForm()

    if form.validate_on_submit():
        username = form.data['username']
        password = form.data['password']

        user = User.authenticate(username, password)

        if user:
            session["username"] = user.username
            return redirect(f'/users/{user.username}')
        else:
            form.username.errors.append('Username or Password incorrect!')
            return render_template('login_form.html', form=form)

    else: 
        return render_template('login_form.html', form=form)

@app.route('/logout')
def logout_user():
    """Logs out the user"""

    session.pop("username")

    return redirect('/login')

# ROUTES FOR USERS AND FEEDBACK

@app.route('/users/<username>/feedback/add', methods=['POST', 'GET'])
def add_feedback(username):
    """Show logged in user feedback form and process form"""

    if not check_authorization(username):
        return redirect('/404')

    form = FeedbackForm()

    if form.validate_on_submit():
        title = form.data["title"]
        content = form.data["content"]
        
        feedback = Feedback(title=title, content=content, username=username)
        
        db.session.add(feedback)
        db.session.commit()

        return redirect(f'/users/{username}')

    else:
        return render_template('feedback_form.html', form=form)

@app.route('/users/<username>/feedback/<feedback_id>/update', methods=['GET', 'POST'])
def edit_feedback(username, feedback_id):
    """Show logged in user a form to edit feedback"""

    user = check_authorization(username)

    feedback = Feedback.query.get_or_404(feedback_id)
    form = FeedbackForm(obj=feedback)

    if form.validate_on_submit():
        feedback.title = form.data["title"]
        feedback.content = form.data["content"]
        
        db.session.commit()

        return redirect(f'/users/{username}')

    else:
        return render_template('edit_feedback_form.html', form=form, user=user)

@app.route('/users/<username>/feedback/<feedback_id>/delete', methods=['POST'])
def delete_feedback(username, feedback_id):
    """Delete feedback"""

    user = check_authorization(username)

    if not user:
        return redirect('/404')

    feedback = Feedback.query.get_or_404(feedback_id)

    if feedback.username == user.username:
        
        db.session.delete(feedback)
        db.session.commit()

        return redirect(f'/users/{username}')
    
    else:
        raise Unauthorized()