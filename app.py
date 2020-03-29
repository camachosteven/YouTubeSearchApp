import os
import json
import requests
from os import environ as env
from functools import wraps
from dotenv import load_dotenv, find_dotenv
from flask import Flask, render_template, flash, request, url_for, redirect, Response, jsonify, session
from importlib import import_module
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_sqlalchemy import SQLAlchemy
from apiclient.errors import HttpError
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode
from werkzeug.exceptions import HTTPException
from search import SearchVideo, SelectVideo, requestVideo, ControlStream

# import camera driver
if os.environ.get('CAMERA'):
    Camera = import_module('camera_' + os.environ['CAMERA']).Camera
else:
    from camera import Camera

app = Flask(__name__)
app.config['SECRET_KEY'] = '3639b04fec10c30d78aabea1727078e0'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)
oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id = 'XXV26umazQFUjh0i6F9ObZaXoWlzixfq',
    client_secret = 'H9CRjJOoq08jjVh9zubbTXq8oIytP9QUStdqEqOa-ZJiMceAtB0qJkxR29Bzz7ds',
    api_base_url='https://dev-xpds945m.auth0.com',
    access_token_url='https://dev-xpds945m.auth0.com/oauth/token',
    authorize_url='https://dev-xpds945m.auth0.com/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
)

class VideoSelections(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    video_id = db.Column(db.String(11))


def requires_auth(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    if 'profile' not in session:
      # Redirect to Login page here
      return redirect(url_for('login'))
    return f(*args, **kwargs)
  return decorated

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

@app.route("/")
def home():
    return render_template('base.html')

@app.route("/stored", methods=["GET", "POST"])
@requires_auth
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
@requires_auth
def live():
    form = ControlStream()
    if form.select.data == 'Start':
        return render_template('live.html', title="Live", form=form, start=True)
    return render_template('live.html', title="Live", form=form, start=False)

@app.route("/videofeed")
def videofeed():
    return Response(gen(Camera()),
                    mimetype='multipart/x-mixed-replace; boundary=frame')
    
@app.route("/login", methods=["GET", "POST"])
def login():
    return auth0.authorize_redirect(redirect_uri='http://localhost:5000/callback')

@app.route("/callback")
def callback():
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()
    session['jwt_payload'] = userinfo
    session['profile'] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
    return redirect(url_for('stored'))

@app.route("/logout")
def logout():
    session.clear()
    params = {
        'returnTo': url_for('home', _external=True),
        'client_id': 'XXV26umazQFUjh0i6F9ObZaXoWlzixfq',
    }
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))

@app.route("/contact")
@requires_auth
def contact():
    return render_template('contact.html', title="Contact")
    
if __name__ == "__main__":
    app.run(debug=True)