from flask import Flask, request, render_template, flash, redirect, url_for
app = Flask(__name__)

from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import (LoginManager, login_user, logout_user, user_logged_in, current_user, user_logged_out, login_required)

import ble_coms
import hashlib, time


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fyp.db'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(120))

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def get_id(self):
        return self.id

    def is_active(self):
        return True

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def __repr__(self):
        return '<User %r>' % self.username

class Node(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    node_addr = db.Column(db.String(80), unique=True)
    primary = db.Column(db.Boolean())
    last_seen = db.Column(db.Integer)

    def __init__(self, node_addr, primary=False):
        self.node_addr = node_addr
        self.primary = primary

    def __repr__(self):
        return '<Node %r>' % self.node_addr

@login_manager.user_loader
def load_user(userid):
    return User.query.filter_by(id=userid).first()

def valid_login(username, password):
    user = User.query.filter_by(username=username).first()
    return (user is not None) and (user.password == hashlib.sha256(password).hexdigest())

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    nodes = Node.query.all()
    return render_template('dashboard.html', nodes=nodes)

@app.route('/node/<node_id>')
@login_required
def node_view(node_id):
    node = Node.query.get(node_id)
    return render_template('node.html', node=node)

@app.route('/node/create', methods=['POST'])
@login_required
def node_create():
    if "hex" in request.form:
        node = Node(request.form['hex'])
        db.session.add(node)
        db.session.commit()
        flash('New node successfully added')
    else:
        flash('Failed to create new node')
    return redirect(url_for('dashboard'))

@app.route('/ping/<node_id>')
@login_required
def ping(node_id):
    node = Node.query.get(node_id)
    ble_coms.send_ping(node.node_addr)
    return "Ping'd"

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/login', methods=['POST', 'GET'])
def login():
    error = None
    if request.method == 'POST':
        if "username" in request.form and "password" in request.form and valid_login(request.form['username'],
                       request.form['password']):
            user = User.query.filter_by(username=request.form['username']).first()
            login_user(user)
            flash('You were successfully logged in')
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid username/password'
    # the code below is executed if the request method
    # was GET or the credentials were invalid
    return render_template('login.html', error=error)

if __name__ == '__main__':
    app.debug = True
    app.secret_key = '\x0f\xc1\xe9M{r\x98\x91\x85f\xa7\x8b\xdd)\x05\xc7@\xd5{\xd6\x99$V\xca'
    app.run(host='0.0.0.0')
