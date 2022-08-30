from flask import Flask, render_template, url_for, redirect, request, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import requests
import json
from elasticsearch6 import Elasticsearch
import os 

es = Elasticsearch("http://localhost:9200/")
app = Flask(__name__)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    length = 0
    return render_template('dashboard.html', leng=length)


@app.route("/dashboard/results", methods=['GET', 'POST'])
@login_required
def request_search():
    search_term = request.form['input']
    res = es.search(
        index='catalogue',
        body={"query": {"multi_match": {"query": search_term, "fields": ["name", "subtopics", "Department", "Year", "Module_learder"]}}})

    resp = json.dumps(res)
    respo = json.loads(resp)
    length = len(respo['hits']['hits'])
    return render_template('dashboard.html', res=respo, leng=length)


@app.route('/dashboard/pageModule/', methods=['GET', 'POST'])
@login_required
def pageModule():
    topic = request.form['topic']
    res = es.search(
        index='catalogue',
        body={"query":{"match" : {"name":topic}}})
    resp = json.dumps(res)
    respo = json.loads(resp)

    title = respo['hits']['hits'][0]['_source']['name']
    all_lec = sorted(os.listdir("/Users/leonardosaeta/Documents/Git/Modules-Search-Engine/App/Modules/"+title))
    all_lec_len = len(all_lec)
    return render_template('module-page.html', title=respo, all_lec=all_lec, all_lec_len=all_lec_len)

@app.route('/download', methods=['GET', 'POST'])
def download_file():
    test = request.form['category']
    print(test)
    topic = request.form['lecture']
    print(topic)
    path = "/Users/leonardosaeta/Documents/Git/Modules-Search-Engine/App/Modules/"+test+"/"+topic
    print(path)
    return send_file(path, as_attachment=True)

@app.route('/modules', methods=['GET', 'POST'])
@login_required
def modules():
    req = requests.get('http://localhost:9200/catalogue/modules/_search')
    data = req.content
    json_data = json.loads(data)
    data_length = len(json_data['hits']['hits'])
    return render_template('modules.html', data=json_data, length=data_length)


@ app.route('/upload', methods=['GET', 'POST'])
@ login_required
def upload():
    return render_template('upload.html')


@ app.route('/logout', methods=['GET', 'POST'])
@ login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


if __name__ == "__main__":
    app.run(debug=True)
