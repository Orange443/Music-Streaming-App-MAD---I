from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session
from models import db, User, Song, Album, Playlist, PlaylistSong, CreatorBlacklist
from app import app
from werkzeug.security import check_password_hash


def auth_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to access this page.')
            return redirect(url_for('login')) 
        return func(*args, **kwargs)
    return inner

@app.route('/')
@auth_required
def index():
    return render_template('index.html', user=User.query.get(session['user_id']))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')
    admin_login = request.form.get('admin_login')

    if username == '' or password == '':
        flash('Please fill out all fields')
        return redirect(url_for('login'))
    
    if username == 'admin':
        flash('If you are an admin, please log in as an admin using the admin login page.')
        return redirect(url_for('login'))

    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        flash('Invalid username or password')
        return redirect(url_for('login'))

    if admin_login:
        if user.is_admin:
            session['user_id'] = user.user_id
            return redirect(url_for('admin_dashboard'))
        else:
            flash('You are not authorized to access the admin panel.')
            return redirect(url_for('login'))

    session['user_id'] = user.user_id
    return redirect(url_for('index'))

@app.route('/admin_login')
def admin_login():
    return render_template('admin_login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    # Check if the user is authenticated as an admin
    user_id = session.get('user_id')
    if user_id is not None:
        user = User.query.get(user_id)
        if user.is_admin:
            # Render the admin dashboard template
            return render_template('admin_dashboard.html', user=user)
    
    flash('You are not authorized to access the admin dashboard.')
    return redirect(url_for('login'))

@app.route('/admin_login', methods=['POST'])
def admin_login_post():
    username = request.form.get('username')
    password = request.form.get('password')

    if username == '' or password == '':
        flash('Please fill out all fields')
        return redirect(url_for('admin_login'))

    admin_user = User.query.filter_by(username=username, is_admin=True).first()

    if not admin_user or not admin_user.check_password(password):
        flash('Invalid admin username or password')
        return redirect(url_for('admin_login'))

    session['user_id'] = admin_user.user_id
    return redirect(url_for('admin_dashboard'))

@app.route('/register') 
def login_register_page():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register_post():
    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    role = request.form.get('role') 
    if username == '' or password == '' or confirm_password == '' or not role:
        flash('Please fill out all fields and select a role')
        return redirect('register')
    if password != confirm_password:
        flash('Password and confirm password do not match. Please try again.')
        return redirect('register')
    if User.query.filter_by(username=username).first():
        flash('Username already in use. Please choose a different username.')
        return redirect('register')

    user = User(username=username, role=role)  
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    flash('Registration successful. You can now log in.')
    return redirect(url_for('login'))

'''@app.route('/signup_as_creator')
@auth_required
def signup_as_creator():
    return render_template('signup_as_creator.html')'''

@app.route('/signup_as_creator', methods=['GET'])
@auth_required
def signup_as_creator():
    return render_template('signup_as_creator.html')

@app.route('/change_role_to_creator', methods=['POST'])
@auth_required
def change_role_to_creator():
    # Get the current user
    user = User.query.get(session['user_id'])
    
    # Change the user's role to 'Creator' and update the database
    user.role = 'Creator'
    db.session.commit()
    
    flash('Congratulations! You are now a Creator.')
    return redirect(url_for('index'))


@app.route('/your_playlists')
@auth_required
def your_playlists():
    return render_template('your_playlists.html')  

@app.route('/creator_dashboard')
@auth_required
def creator_dashboard():
    return render_template('creator_dashboard.html')