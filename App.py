from flask_login import LoginManager, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length
from flask import render_template, redirect, url_for, flash
import feedparser
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, logout_user, login_required
from flask import Flask, request, make_response
from sqlalchemy import text
from lxml import etree
import uuid
import os
import logging
import time
from datetime import datetime
from werkzeug.utils import secure_filename
from functools import wraps

# Create 'logs' directory if it doesn't exist
if not os.path.exists('logs'):
    os.makedirs('logs')

# Configure logging
logging.basicConfig(filename=f'logs/access_{datetime.now().strftime("%Y_%m_%d")}.log',
                    level=logging.INFO,
                    format='%(asctime)s %(levelname)s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

app = Flask(__name__)
FEED_URL = "https://rss.haberler.com/rss.asp?kategori=universite"
# FEED_URL = "https://dergipark.org.tr/tr/pub/uad/rss/lastissue/en"
app.config['SECRET_KEY'] = '1234'
UPLOAD_FOLDER = 'static'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def log_search(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Gather request details
        log_details = {
            "eventid": "search",
            "message": "Request received",
            "url": request.path,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "unixtime": time.time(),
            "src_ip": request.remote_addr,
            "src_port": request.environ.get('REMOTE_PORT'),
            "dst_port": request.environ.get('SERVER_PORT'),
            "request": request.method,
            "user_agent": request.headers.get('User-Agent'),
            "accept_language": request.headers.get('Accept-Language'),
            "dst_ip": request.host.split(':')[0]  # Assumes default http format
        }

        # Log query parameters and form data if they exist
        if request.args:
            log_details["query_params"] = dict(request.args)
        if request.form:
            log_details["form_data"] = dict(request.form)
        if request.data and request.is_json:
            log_details["json_data"] = request.get_json(silent=True)

        # Log the details
        logging.info(f"Activity: {log_details}")

        return f(*args, **kwargs)
    return decorated_function

def log_cookie(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Gather request details
        log_details = {
            "eventid": "cookie",
            "message": "Request received",
            "url": request.path,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "unixtime": time.time(),
            "src_ip": request.remote_addr,
            "src_port": request.environ.get('REMOTE_PORT'),
            "dst_port": request.environ.get('SERVER_PORT'),
            "request": request.method,
            "user_agent": request.headers.get('User-Agent'),
            "accept_language": request.headers.get('Accept-Language'),
            "dst_ip": request.host.split(':')[0]  # Assumes default http format
        }

        # Log query parameters and form data if they exist
        if request.args:
            log_details["query_params"] = dict(request.args)
        if request.form:
            log_details["form_data"] = dict(request.form)
        if request.data and request.is_json:
            log_details["json_data"] = request.get_json(silent=True)

        # Log the details
        logging.info(f"Activity: {log_details}")

        return f(*args, **kwargs)
    return decorated_function

def log_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Gather request details
        log_details = {
            "eventid": "authentication",
            "message": "Request received",
            "url": request.path,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "unixtime": time.time(),
            "src_ip": request.remote_addr,
            "src_port": request.environ.get('REMOTE_PORT'),
            "dst_port": request.environ.get('SERVER_PORT'),
            "request": request.method,
            "user_agent": request.headers.get('User-Agent'),
            "accept_language": request.headers.get('Accept-Language'),
            "dst_ip": request.host.split(':')[0]  # Assumes default http format
        }
        # Log query parameters and form data if they exist
        if request.args:
            log_details["query_params"] = dict(request.args)
        if request.form:
            log_details["form_data"] = dict(request.form)
        if request.data and request.is_json:
            log_details["json_data"] = request.get_json(silent=True)

        # Log the details
        logging.info(f"Activity: {log_details}")

        return f(*args, **kwargs)
    return decorated_function

def log_comment(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Gather request details
        log_details = {
            "eventid": "comment",
            "message": "Request received",
            "url": request.path,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "unixtime": time.time(),
            "src_ip": request.remote_addr,
            "src_port": request.environ.get('REMOTE_PORT'),
            "dst_port": request.environ.get('SERVER_PORT'),
            "request": request.method,
            "user_agent": request.headers.get('User-Agent'),
            "accept_language": request.headers.get('Accept-Language'),
            "dst_ip": request.host.split(':')[0]  # Assumes default http format
        }

        # Log query parameters and form data if they exist
        if request.args:
            log_details["query_params"] = dict(request.args)
        if request.form:
            log_details["form_data"] = dict(request.form)
        if request.data and request.is_json:
            log_details["json_data"] = request.get_json(silent=True)

        # Log the details
        logging.info(f"Activity: {log_details}")

        return f(*args, **kwargs)
    return decorated_function

def log_news(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Gather request details
        log_details = {
            "eventid": "news",
            "message": "Request received",
            "url": request.path,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "unixtime": time.time(),
            "src_ip": request.remote_addr,
            "src_port": request.environ.get('REMOTE_PORT'),
            "dst_port": request.environ.get('SERVER_PORT'),
            "request": request.method,
            "user_agent": request.headers.get('User-Agent'),
            "accept_language": request.headers.get('Accept-Language'),
            "dst_ip": request.host.split(':')[0]  # Assumes default http format
        }

        # Log query parameters and form data if they exist
        if request.args:
            log_details["query_params"] = dict(request.args)
        if request.form:
            log_details["form_data"] = dict(request.form)
        if request.data and request.is_json:
            log_details["json_data"] = request.get_json(silent=True)

        # Log the details
        logging.info(f"Activity: {log_details}")

        return f(*args, **kwargs)
    return decorated_function

def log_profile(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Gather request details
        log_details = {
            "eventid": "profile",
            "message": "Request received",
            "url": request.path,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "unixtime": time.time(),
            "src_ip": request.remote_addr,
            "src_port": request.environ.get('REMOTE_PORT'),
            "dst_port": request.environ.get('SERVER_PORT'),
            "request": request.method,
            "user_agent": request.headers.get('User-Agent'),
            "accept_language": request.headers.get('Accept-Language'),
            "dst_ip": request.host.split(':')[0]  # Assumes default http format
        }

        # Log query parameters and form data if they exist
        if request.args:
            log_details["query_params"] = dict(request.args)
        if request.form:
            log_details["form_data"] = dict(request.form)
        if request.data and request.is_json:
            log_details["json_data"] = request.get_json(silent=True)

            # Log the file content if an upload is part of the request
            if 'file_field_name' in request.files:  # Replace 'file_field_name' with your actual file field's name
                file = request.files['file_field_name']
                if file:  # checking if file is not empty
                    # Read the content of the file
                    file_content = file.read()
                    # Ensure you don't log too large files, or consider saving content to a secure location
                    if len(file_content) < 1024:  # Only log if content is less than 1KB for example
                        log_details["file_content"] = file_content.decode("utf-8",
                                                                          errors="ignore")  # decoding bytes to string

                    # Reset file pointer if the file is used later
                    file.seek(0)

        # Log the details
        logging.info(f"Activity: {log_details}")

        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/search")
@log_search
def search():
    query = request.args.get('query', '')
    feed = feedparser.parse(FEED_URL)
    filtered_news = []
    filtered_users = []

    if query:
        # Filtering the news based on the query
        for entry in feed.entries:
            if query.lower() in entry.title.lower() or query.lower() in entry.description.lower():
                filtered_news.append(entry)

        # Vulnerable SQL query
        raw_sql = text(f"SELECT * FROM user WHERE username LIKE '%{query}%'")
        result = db.session.execute(raw_sql)
        filtered_users = [dict(row._asdict()) for row in result]

    return render_template('search_results.html', news=filtered_news, users=filtered_users, query=query)

def process_xml(xml_file):
    try:
        parser = etree.XMLParser(load_dtd=True, no_network=False)  # Insecure configuration
        tree = etree.parse(xml_file, parser=parser)
        root = tree.getroot()

        # Extract profile image and about info from XML
        profile_image = root.find('profile_image').text
        about = root.find('about').text

        return profile_image, about
    except Exception as e:
        print(f"Error processing XML: {e}")
        return None, None

@app.route('/set_cookie')
@log_cookie
def set_cookie():
    response = make_response("Cookie is set")
    # Storing sensitive information in a cookie in cleartext
    response.set_cookie('sensitive_data', 'user_password_or_other_sensitive_info')
    return response

@app.route('/get_cookie')
@log_cookie
def get_cookie():
    sensitive_data = request.cookies.get('sensitive_data', 'Not Set')
    return f"Sensitive Data from Cookie: {sensitive_data}"

# MySQL configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/News'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))  # Updated field name
    is_admin = db.Column(db.Boolean, default=False)  # field to indicate admin status
    profile_image = db.Column(db.String(255))  # URL to the profile image
    about = db.Column(db.Text)  # About information

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = password

    def verify_password(self, password):
        return self.password_hash == password


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete= "SET NULL"))
    article_title = db.Column(db.String(200))  # You may adjust the size as needed
    user = db.relationship('User')  # Add a relationship to the User model

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=100)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=100)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class CommentForm(FlaskForm):
    content = TextAreaField('Comment', validators=[DataRequired()])
    submit = SubmitField('Post Comment')

@app.route('/profile/<username>', methods=['GET', 'POST'])
@login_required
@log_profile
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()

    if request.method == 'POST' and (current_user.username == username or current_user.is_admin):
        xml_file = request.files.get('xml_file')  # The XML file input from the form

        if xml_file:
            # Read the entire content of the XML file
            xml_content = xml_file.read()
            # Log the raw XML data
            logging.info(f"Received XML content for user {username}: {xml_content}")

            # Reset the file pointer if you're going to use the file again
            xml_file.seek(0)
            # Process the XML file
            profile_image, about = process_xml(xml_file)

            # Truncate or handle the data if it's too large for your database schema
            max_length = 255  # or whatever your column's maximum length is
            profile_image = (profile_image[:max_length]) if profile_image else None

            # Update user profile with the extracted data
            if profile_image:
                user.profile_image = profile_image  # Update the profile image URL
            if about:
                user.about = about  # Update the about text

            flash('Profile updated successfully!')

        else:
            if 'profile_image' in request.files:
                file = request.files['profile_image']
                if file: #and allowed_file(file.filename):
                    # Secure the filename
                    filename = secure_filename(file.filename)

                    # Generate a unique filename
                    extension = filename.rsplit('.', 1)[1].lower()
                    unique_filename = f"{uuid.uuid4()}.{extension}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

                    # Delete existing image if it exists and is not default
                    if user.profile_image and os.path.exists("static/" + user.profile_image) and 'default_profile.jpg' not in user.profile_image:
                        os.remove("static/" + user.profile_image)

                    # Save new image
                    file.save(file_path)
                    user.profile_image = file_path[len("static/"):]

            about = request.form.get('about')
            if about:
                user.about = about

        # Save changes to database
        db.session.commit()
        flash('Profile updated successfully!')
        return redirect(url_for('profile', username=username))

    return render_template('profile.html', user=user)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@log_profile
def delete_user(user_id):
    if not current_user.is_admin:
        flash("You do not have permission to delete users.")
        return redirect(url_for('print_news'))

    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.is_admin:
        flash("Cannot delete admin users.")
        return redirect(url_for('print_news'))

    db.session.delete(user_to_delete)
    db.session.commit()
    flash('User deleted successfully.')
    return redirect(url_for('print_news'))

@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
@log_comment
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if current_user.is_admin or comment.user_id == current_user.id:
        db.session.delete(comment)
        db.session.commit()
        flash('Comment deleted successfully.')
    else:
        flash('You do not have permission to delete this comment.')
    return redirect(url_for('news_detail', title=comment.article_title))



@app.route('/register', methods=['GET', 'POST'])
@log_auth
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user is None:
            new_user = User(username=username)
            new_user.password = password  # This uses the password setter
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        else:
            flash('Username already exists')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@log_auth
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and user.verify_password(password):
            login_user(user)

            # Set a cookie with sensitive information (for demonstration only)
            response = make_response(redirect(url_for('print_news')))
            response.set_cookie('sensitive_data', 'Username: {}; Password: {}'.format(username, password))
            return response
        else:
            flash('Invalid username or password')

    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('print_news'))

@app.route('/comment', methods=['POST'])
@login_required
@log_comment
def comment():
    content = request.form['content']
    article_title = request.form['article_title']  # Ensure this is passed correctly

    new_comment = Comment(content=content, user_id=current_user.id, article_title=article_title)
    db.session.add(new_comment)
    db.session.commit()

    return redirect("/news/" + article_title)


@app.route("/")
@log_news
def print_news():
    feed = feedparser.parse(FEED_URL)
    return render_template('news_list.html', news=feed.entries)

@app.route("/news/<title>")
@log_news
def news_detail(title):
    feed = feedparser.parse(FEED_URL)
    selected_news = next((item for item in feed.entries if item.title == title), None)
    comments = Comment.query.filter_by(article_title=title).all()
    return render_template('news_detail.html', news_item=selected_news, comments=comments)



if __name__ == "__main__":
    app.run()
