from flask_wtf import FlaskForm
from os import environ as env
from apiclient.discovery import build
from wtforms import StringField, SelectField, SubmitField
from wtforms.validators import DataRequired, Length, NumberRange

class SearchVideo(FlaskForm):
    query = StringField('Query', 
    validators=[DataRequired(), Length(min=5, max=75)])
    size = SelectField('Response Size', 
    choices=[('3', ' '), ('1', '1'), ('2', '2'), ('3', '3'), ('4', '4'), ('5', '5')])
    submit = SubmitField('Search')


def requestVideo(query: str, size: int):
    api_key = env.get('YOUTUBE')
    youtube = build('youtube', 'v3', developerKey=api_key)
    api_req = youtube.search().list(part='snippet', q=query, maxResults=size, type='video')
    return api_req.execute()

class SelectVideo(FlaskForm):
    videoNumber = SelectField('Video Number', validators=[DataRequired()], coerce=int)
    submit = SubmitField('Select')


class ControlStream(FlaskForm):
    select = SelectField('VideoNumber',
    choices=[('Start', 'Start'), ('Stop', 'Stop')])
    execute = SubmitField('Execute')