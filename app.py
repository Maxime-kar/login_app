import os
import re
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Folder to store user files
USER_FOLDER = 'users'
os.makedirs(USER_FOLDER, exist_ok=True)

# Password validation regex pattern
PASSWORD_PATTERN = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'

# Utility functions
def get_user_file(username):
    return os.path.join(USER_FOLDER, f"{username}.txt")

def user_exists(username):
    return os.path.exists(get_user_file(username))

def save_user(username, password, full_name, email):
    hashed = generate_password_hash(password)
    with open(get_user_file(username), 'w') as f:
        f.write(f"hashed_password:{hashed}\n")
        f.write(f"full_name:{full_name}\n")
        f.write(f"email:{email}\n")

def get_user_info(username):
    if not user_exists(username):
        return None
    with open(get_user_file(username), 'r') as f:
        lines = f.readlines()
        user_info = {}
        for line in lines:
            key, value = line.strip().split(':', 1)
            user_info[key] = value
        return user_info

def check_user_credentials(username, password):
    user_info = get_user_info(username)
    if user_info is None:
        return False
    stored_hash = user_info['hashed_password']
    return check_password_hash(stored_hash, password)

# Password validation function
def is_valid_password(password):
    if re.match(PASSWORD_PATTERN, password):
        return True
    return False

# Routes
@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if check_user_credentials(username, password):
            session['user'] = username
            return redirect(url_for('home'))
        else:
            error = 'Invalid username or password'
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        full_name = request.form['full_name']
        email = request.form['email']
        
        # Check if username already exists
        if user_exists(username):
            error = 'Username already exists'
        
        # Validate password
        elif not is_valid_password(password):
            error = ('Password must have at least 8 characters, '
                      'one uppercase letter, one lowercase letter, one number, '
                      'and one special character.')
        
        # If no errors, save the new user
        else:
            save_user(username, password, full_name, email)
            return redirect(url_for('login'))
    
    return render_template('register.html', error=error)

@app.route('/home')
def home():
    if 'user' in session:
        user_info = get_user_info(session['user'])
        return render_template('home.html', user=session['user'], full_name=user_info['full_name'])
    return redirect(url_for('login'))

@app.route('/profile')
def profile():
    if 'user' in session:
        user_info = get_user_info(session['user'])
        return render_template('profile.html', user_info=user_info)
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
