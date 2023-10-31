from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session
from models import db, User, Song, Album, Playlist, PlaylistSong, CreatorBlacklist
from app import app
from sqlalchemy import func, distinct
from werkzeug.security import check_password_hash
import time
import re
import datetime




def auth_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to access this page.')
            return redirect(url_for('login')) 
        return func(*args, **kwargs)
    return inner

def admin_reqequired(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to access this page.')
            return redirect(url_for('login')) 
        user = User.query.get(session['user_id'])
        if not user.is_admin:
            flash('You must be an admin to access this page.')
            return redirect(url_for('index'))
        return func(*args, **kwargs)
    return inner

def creator_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to access this page.')
            return redirect(url_for('login')) 
        user = User.query.get(session['user_id'])
        if not user.role == 'Creator':
            flash('You must be a creator to access this page.')
            return redirect(url_for('index'))
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
@admin_reqequired
def admin_dashboard():
    # Check if the user is authenticated as an admin
    user_id = session.get('user_id')
    if user_id is not None:
        user = User.query.get(user_id)
        if user.is_admin:
            # Gather and pass statistics to the template
            total_users = User.query.count()
            total_creators = User.query.filter_by(role='Creator').count()
            total_albums = Album.query.count()
            distinct_genres = db.session.query(func.count(distinct(Album.genre))).scalar()
            return render_template(
                'admin_dashboard.html',
                distinct_genres=distinct_genres, 
                user=user, 
                total_users=total_users,
                total_creators=total_creators, 
                total_albums=total_albums)  
    
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
    created_songs = Song.query.filter_by(creator_id=session['user_id']).all()
    
    # Change the user's role to 'Creator' and update the database
    user.role = 'Creator'

    db.session.commit()
    
    flash('Congratulations! You are now a Creator.', 'success')
    return redirect(url_for('index'))


@app.route('/your_playlists')
@auth_required
def your_playlists():
    return render_template('your_playlists.html')  

@app.route('/creator_dashboard')
@creator_required
def creator_dashboard():
    user = User.query.get(session['user_id'])
    albums = user.created_albums
    return render_template('creator_dashboard.html', user=user,albums=albums)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/albums/add')
@creator_required
def add_album():
    return render_template('albums/add.html',user=User.query.get(session['user_id']))

@app.route('/albums/add', methods=['POST'])
@creator_required
def add_album_post():
    title = request.form.get('title')
    if title == '':
        flash('Please enter a title')
        return redirect(url_for('add_album'))
    release_date = request.form.get('release_date')
    if release_date:
        try:
            release_date = datetime.datetime.strptime(release_date, '%Y-%m-%d')
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD.')
            return redirect(url_for('add_product'))
        
    genre = request.form.get('genre')
    album = Album(title=title, release_date=release_date, genre=genre, creator_id=session['user_id'])
    db.session.add(album)
    db.session.commit()
    flash('Album added successfully', 'success')
    return redirect(url_for('creator_dashboard'))

@app.route('/create_song', methods=['GET', 'POST'])
@creator_required
def create_song():
    if request.method == 'POST':
        # Retrieve data from the form
        title = request.form.get('title')
        artist = request.form.get('artist')
        lyrics = request.form.get('lyrics')
        genre = request.form.get('genre')

        # Create a new Song object and add it to the database
        new_song = Song(title=title, artist=artist, lyrics=lyrics, genre=genre, creator_id=session['user_id'])
        db.session.add(new_song)
        db.session.commit()

        flash('New song created successfully', 'success')
        return redirect(url_for('creator_dashboard'))

    return render_template('create_song.html')

@app.route('/edit_song/<int:song_id>', methods=['GET', 'POST'])
@creator_required
def edit_song(song_id):
    song = Song.query.get(song_id)

    if not song:
        return "Song not found"

    if request.method == 'POST':
        # Retrieve data from the form for editing
        song.title = request.form.get('title')
        song.artist = request.form.get('artist')
        song.lyrics = request.form.get('lyrics')
        song.genre = request.form.get('genre')

        # Update the song in the database
        db.session.commit()

        flash('Song updated successfully', 'success')
        return redirect(url_for('creator_dashboard'))

    return render_template('edit_song.html', song=song)

@app.route('/albums/<int:album_id>/delete')
@creator_required
def delete_album(album_id):
    return render_template('albums/delete.html', user=User.query.get(session['user_id']), album=Album.query.get(album_id))

@app.route('/album/<int:album_id>/delete', methods=['POST'])
@creator_required
def delete_album_post(album_id):
    # Retrieve the album with the given ID from the database
    album = Album.query.get(album_id)
    if not album:
        flash('Album not found', 'error')
        return redirect(url_for('creator_dashboard'))
    
    if album.creator_id != session['user_id']:
        flash('You do not have permission to delete this album', 'error')
        return redirect(url_for('creator_dashboard'))
    
    db.session.delete(album)
    db.session.commit()
    flash('Album deleted successfully', 'success')
    return redirect(url_for('creator_dashboard'))

@app.route('/albums/<int:album_id>/edit')
@creator_required
def edit_album(album_id):
    pass

@app.route('/albums/<int:album_id>/show')
@creator_required
def show_album(album_id):
    pass