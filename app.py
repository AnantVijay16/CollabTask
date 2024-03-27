from flask import *
from flask_pymongo import PyMongo
from pymongo import MongoClient
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import secrets
import string
import json
from bson.objectid import ObjectId
import datetime
import unittest
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, EmailField
from wtforms.validators import DataRequired, Email, EqualTo
from functools import wraps
from flask import abort
import os
from werkzeug.utils import secure_filename
from pytz import utc

app = Flask(__name__)

# Load configuration from config.json
with open('config.json') as f:
    params = json.load(f)['param']

app.config['SECRET_KEY'] = params['SECRET_KEY']
app.config['MONGO_URI'] = params['MONGO_URI']
app.config['MAIL_SERVER'] = params['MAIL_SERVER']
app.config['MAIL_PORT'] = params['MAIL_PORT']
app.config['MAIL_USE_TLS'] = params['MAIL_USE_TLS']
app.config['MAIL_USERNAME'] = params['gmail-user']
app.config['MAIL_PASSWORD'] = params['gmail-password']

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
mail = Mail(app)

client = MongoClient(params['MONGO_URI'])
db = client["CollabTask"]  # Connect to the "CollabTask" database

@login_manager.user_loader
def load_user(user_id):
    return db.users.find_one({'_id': ObjectId(user_id)})

class User(UserMixin):
    def __init__(self, user_data):
        self.user_data = user_data

    def get_id(self):
        return ObjectId(self.user_data['_id'])

class ResetPasswordRequestForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

def send_password_reset_email(user_email):
    # Your logic to send the password reset email goes here
    pass

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('confirm_password')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Reset Password')

class ProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update Profile')

class TaskForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    assignee = SelectField('Assignee', coerce=str, validators=[DataRequired()])
    due_date = StringField('Due Date', validators=[DataRequired()])
    submit = SubmitField('Create Task')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        session['email'] = email

        # Check if a user with the same email address already exists
        existing_user = db.users.find_one({'email': email})
        if existing_user:
            if existing_user['verified']:
                flash('Your email has already been verified. You can log in now.', 'success')
                return redirect(url_for('login'))
            else:
                # Generate new OTP
                otp = generate_otp()

                # Update user's OTP in the database
                db.users.update_one({'_id': existing_user['_id']}, {'$set': {'otp': otp}})

                # Send OTP via email
                msg = Message('Verify Your Email', sender=app.config['MAIL_USERNAME'], recipients=[email])
                msg.body = f'Your OTP for verification: {otp}'
                mail.send(msg)
                session['expiry_time'] = utc.localize(datetime.datetime.utcnow()) + datetime.timedelta(minutes=5)

                flash('A new verification OTP has been sent to your email. Please check and enter it below.', 'success')
                return redirect(url_for('verify'))

        # Generate OTP
        otp = generate_otp()

        # Send OTP via email
        msg = Message('Verify Your Email', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f'Your OTP for verification: {otp}'
        mail.send(msg)

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user_data = {'username': username, 'email': email, 'password': hashed_password, 'otp': otp, 'verified': False}
        db.users.insert_one(user_data)
        
        flash('A verification OTP has been sent to your email. Please check and enter it below.', 'success')

        session['expiry_time'] = utc.localize(datetime.datetime.utcnow()) + datetime.timedelta(minutes=5)

        return redirect(url_for('verify'))
    return render_template('signup.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        if 'expiry_time' in session and utc.localize(datetime.datetime.utcnow()) > session['expiry_time']:
            return "OTP expired. Please register again."
        
        otp = request.form['otp']
        email = session.get('email')

        user = db.users.find_one({'email': email, 'otp': otp})
        if user:
            db.users.update_one({'_id': user['_id']}, {'$set': {'verified': True}})
            flash('Your email has been verified. You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
    return render_template('verify.html')

@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    email = request.json.get('email')
    if not email:
        return jsonify({'success': False, 'message': 'Email is required.'}), 400

    user = db.users.find_one({'email': email})
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404

    # Generate new OTP
    otp = generate_otp()

    # Update user's OTP in the database
    db.users.update_one({'_id': user['_id']}, {'$set': {'otp': otp}})

    # Send OTP via email
    msg = Message('Verify Your Email', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f'Your OTP for verification: {otp}'
    mail.send(msg)

    return jsonify({'success': True, 'message': 'OTP has been resent to your email address.'}), 200

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = db.users.find_one({'email': email})
        if user and bcrypt.check_password_hash(user['password'], password) and user['verified']:
            login_user(User(user))
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email, password, or verify your email.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_tasks = db.tasks.find({'assignee_id': str(current_user.get_id())})
    return render_template('dashboard.html', tasks=user_tasks)

@app.route('/create_task', methods=['GET', 'POST'])
@login_required
def create_task():
    if request.method == 'POST':
        form = TaskForm()
        if form.validate_on_submit():
            title = form.title.data
            description = form.description.data
            assignee_id = form.assignee.data
            due_date = form.due_date.data
            task_data = {'title': title, 'description': description, 'assignee_id': assignee_id, 'due_date': due_date, 'status': 'To Do'}
            db.tasks.insert_one(task_data)
            flash('Task has been created!', 'success')
            return redirect(url_for('dashboard'))
    users = db.users.find()
    form = TaskForm()
    form.assignee.choices = [(str(user['_id']), user['username']) for user in users]
    return render_template('create_task.html', users=users, form=form)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()
    if form.validate_on_submit():
        db.users.update_one({'_id': ObjectId(current_user.get_id())}, {'$set': {'username': form.username.data, 'email': form.email.data}})
        flash('Profile updated successfully', 'success')
        return redirect(url_for('profile'))
    elif request.method == 'GET':
        form.username.data = current_user.user_data['username']
        form.email.data = current_user.user_data['email']
    return render_template('profile.html', form=form)


@app.route('/update_task_status/<task_id>/<status>', methods=['POST'])
@login_required
def update_task_status(task_id, status):
    # Update task status in the database
    db.tasks.update_one({'_id': ObjectId(task_id)}, {'$set': {'status': status}})
    flash('Task status updated successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/task_details/<task_id>')
@login_required
def task_details(task_id):
    task = db.tasks.find_one({'_id': ObjectId(task_id)})
    return render_template('task_details.html', task=task)

# Function to send email notification
def send_email(recipient, subject, body):
    msg = Message(subject, sender=app.config['MAIL_USERNAME'], recipients=[recipient])
    msg.body = body
    mail.send(msg)

# Password Reset
# Route for password reset request
@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = db.users.find_one({'email': form.email.data})
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password', 'info')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html', title='Reset Password', form=form)

# Route for password reset
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        db.users.update_one({'_id': ObjectId(user.get_id())}, {'$set': {'password': hashed_password}})
        flash('Your password has been reset.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

# Task Search
@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    if request.method == 'POST':
        search_query = request.form['search_query']
        # Perform search in tasks collection based on search_query
        tasks = db.tasks.find({'$text': {'$search': search_query}})
        return render_template('search_results.html', tasks=tasks)
    return render_template('search.html')

# Task Filtering and Sorting
@app.route('/dashboard_filter_sort', methods=['GET', 'POST'])
@login_required
def dashboard_filter_sort():
    user_tasks = db.tasks.find({'assignee_id': str(current_user.get_id())})
    if request.method == 'POST':
        # Get filter and sort parameters from form submission
        filter_criteria = request.form.get('filter_criteria')
        sort_criteria = request.form.get('sort_criteria')
        # Apply filtering and sorting based on parameters
        if filter_criteria == 'pending':
            user_tasks = user_tasks.filter({'status': 'To Do'})
        elif filter_criteria == 'completed':
            user_tasks = user_tasks.filter({'status': 'Done'})
        if sort_criteria == 'due_date_asc':
            user_tasks = user_tasks.sort('due_date', 1)
        elif sort_criteria == 'due_date_desc':
            user_tasks = user_tasks.sort('due_date', -1)
        # Render template with filtered and sorted tasks
        return render_template('dashboard.html', tasks=user_tasks)
    return render_template('dashboard.html', tasks=user_tasks)

# Decorator to check user roles
def roles_required(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.is_authenticated and \
               any(role['name'] == role for role in current_user.user_data['roles']):
                return f(*args, **kwargs)
            else:
                abort(403)  # Forbidden
        return wrapped
    return wrapper

# Task Comments
class TaskComment:
    def __init__(self, comment, user, task, timestamp=None):
        self.comment = comment
        self.user = user
        self.task = task
        self.timestamp = timestamp or datetime.utcnow()

# Route to add a comment to a task
@app.route('/add_comment/<task_id>', methods=['POST'])
@login_required
def add_comment(task_id):
    task = db.tasks.find_one({'_id': ObjectId(task_id)})
    comment_text = request.form.get('comment')
    if comment_text:
        new_comment = TaskComment(comment=comment_text, user=current_user, task=task)
        task_comments = db.tasks.find_one({'_id': ObjectId(task_id)}, {'comments': 1})
        comments = task_comments.get('comments', [])
        comments.append(new_comment)
        db.tasks.update_one({'_id': ObjectId(task_id)}, {'$set': {'comments': comments}})
        flash('Comment added successfully.', 'success')
    else:
        flash('Cannot add empty comment.', 'warning')
    return redirect(url_for('task_details', task_id=task_id))

# Task Attachments
class TaskAttachment:
    def __init__(self, filename, filepath):
        self.filename = filename
        self.filepath = filepath

# Route to upload attachment to a task
@app.route('/upload_attachment/<task_id>', methods=['POST'])
@login_required
def upload_attachment(task_id):
    task = db.tasks.find_one({'_id': ObjectId(task_id)})
    if 'file' in request.files:
        file = request.files['file']
        if file.filename != '':
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            new_attachment = TaskAttachment(filename=filename, filepath=filepath)
            task_attachments = db.tasks.find_one({'_id': ObjectId(task_id)}, {'attachments': 1})
            attachments = task_attachments.get('attachments', [])
            attachments.append(new_attachment)
            db.tasks.update_one({'_id': ObjectId(task_id)}, {'$set': {'attachments': attachments}})
            flash('Attachment uploaded successfully.', 'success')
        else:
            flash('No file selected.', 'warning')
    return redirect(url_for('task_details', task_id=task_id))

# Error Handling
@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('errors/500.html'), 500

# Pagination
@app.route('/dashboard_pagination', methods=['GET', 'POST'])
@login_required
def dashboard_pagination():
    page = request.args.get('page', 1, type=int)
    skip = (page - 1) * 10
    user_tasks = db.tasks.find({'assignee_id': str(current_user.get_id())}).skip(skip).limit(10)
    return render_template('dashboard.html', tasks=user_tasks)

class FlaskTestCase(unittest.TestCase):

    # Ensure that Flask was set up correctly
    def test_index(self):
        tester = app.test_client(self)
        response = tester.get('/', content_type='html/text')
        self.assertEqual(response.status_code, 200)

    # Ensure that the login page loads correctly
    def test_login_page_loads(self):
        tester = app.test_client(self)
        response = tester.get('/login', content_type='html/text')
        self.assertTrue(b'Login' in response.data)

    # Ensure that the login behaves correctly given the correct credentials
    def test_correct_login(self):
        tester = app.test_client(self)
        response = tester.post('/login', data=dict(email="test@example.com", password="test"), follow_redirects=True)
        self.assertIn(b'Login Successful', response.data)

    # Ensure that the login behaves correctly given the incorrect credentials
    def test_incorrect_login(self):
        tester = app.test_client(self)
        response = tester.post('/login', data=dict(email="wrong@example.com", password="wrong"), follow_redirects=True)
        self.assertIn(b'Invalid email or password', response.data)

# Route for deleting a team
@app.route('/delete_team/<team_id>', methods=['POST'])
@login_required
def delete_team(team_id):
    db.teams.delete_one({'_id': ObjectId(team_id)})
    flash('Team has been deleted!', 'success')
    return redirect(url_for('team_management'))

@app.route('/team_management')
@login_required
def team_management():
    teams = db.teams.find()
    return render_template('team_management.html', teams=teams)

def generate_otp(length=6):
    characters = string.digits
    return ''.join(secrets.choice(characters) for i in range(length))

if __name__ == '__main__':
    app.run(debug=True)
