import os
import json
import requests
from flask import Flask, render_template, flash, request, url_for, redirect, Response
from importlib import import_module
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_sqlalchemy import SQLAlchemy
from apiclient.errors import HttpError
from search import SearchVideo, SelectVideo, requestVideo, ControlStream
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required

# import camera driver
if os.environ.get('CAMERA'):
    Camera = import_module('camera_' + os.environ['CAMERA']).Camera
else:
    from camera import Camera

app = Flask(__name__)
app.config['SECRET_KEY'] = '3639b04fec10c30d78aabea1727078e0'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

class VideoSelections(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    video_id = db.Column(db.String(11))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(60), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)


class RegistrationForm(FlaskForm):
    username = StringField('Username', 
    validators=[DataRequired(), Length(min=5, max=60)])
    password = PasswordField('Password',
    validators=[DataRequired(), Length(min=8)])
    confirm = PasswordField('Confirm Password',
    validators=[DataRequired(), EqualTo('password', 'Confirmation must match password.')])
    register = SubmitField('Register')

    def validate_username(self, name):
        user = User.query.filter_by(username=name.data).first()
        if user:
            raise ValidationError('Username already taken. Please choose another.')


class LoginForm(FlaskForm):
    username = StringField('Username',
    validators=[DataRequired(), Length(min=5, max=20)])
    password = PasswordField('Password',
    validators=[DataRequired()])
    login = SubmitField('Login')


def storeVideoIds(data):
    for video in data["items"]:
        option = VideoSelections(video_id=video["id"]["videoId"])
        db.session.add(option)
    db.session.commit()

def gen(camera):
    while True:
        frame = camera.get_frame()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def home():
    if current_user.is_authenticated:
        flash
    return render_template('base.html')

@app.route("/stored", methods=["GET", "POST"])
@login_required
def stored():
    form = SearchVideo()
    if request.method == "GET":
        return render_template('stored.html', form=form, title="Stored")
    elif request.method == "POST":
        choose = SelectVideo()
        if form.query.data != "":
            if form.validate_on_submit():
                VideoSelections.query.delete()
                db.session.commit()
                query = form.query.data
                size = int(form.size.data)
                form.query.data = ""
                form.size.data = ""
                form.submit.data = False
                try:
                    data = requestVideo(query, size)
                except HttpError as he:
                    flash('At this moment, you cannot watch more videos. Please try again tomorrow.', 'danger')
                    return render_template('stored.html')
                else:
                    flash("You have successfully entered a search.", "success")
                    storeVideoIds(data)
                    choose.videoNumber.choices = [(num, num) for num in range(1, size + 1)]
                    return render_template('stored.html', form=form, 
                    title="Stored", response=data, choose=choose, select=True)
        if choose.videoNumber.data:
            number = int(choose.videoNumber.data)
            desiredVideo = VideoSelections.query.get(number)
            VideoSelections.query.delete()
            db.session.commit()
            flash('Congratulations, you can now watch your desired video.', 'success')
            return render_template('stored.html', form=form, title="Stored", vid=desiredVideo.video_id)
        return render_template('stored.html', form=form, title="Stored")

@app.route("/live", methods=["GET", "POST"])
@login_required
def live():
    form = ControlStream()
    if form.select.data == 'Start':
        return render_template('live.html', title="Live", form=form, start=True)
    return render_template('live.html', title="Live", form=form, start=False)

@app.route("/videofeed")
def videofeed():
    return Response(gen(Camera()),
                    mimetype='multipart/x-mixed-replace; boundary=frame')
    


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        flash('You already logged in. You do not need to register a new account.')
        return redirect(url_for('stored'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = Bcrypt().generate_password_hash(form.password.data).decode("utf-8")
        user = User(username=form.username.data, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        form.username.data = ""
        flash(f'You have sucessfully created a new account as {user.username}!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title="Register", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        flash('You have already logged in. You do not need to login again.')
        return redirect(url_for('stored'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        form.username.data = ""
        if user and Bcrypt().check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            flash(f'You have successfully logged in as {user.username}!', 'success')
            if next_page:
                return redirect(url_for(next_page[1:]))
            else:
                return redirect(url_for('stored'))
        else:
            flash('Login unsuccessful. Please check and email password and try again.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('Logout successful!', 'success')
    return redirect(url_for('login'))

@app.route("/contact")
def contact():
    return render_template('contact.html', title="Contact")
    
if __name__ == "__main__":
    app.run(debug=True)