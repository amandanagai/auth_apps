from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_modus import Modus
import os

app = Flask(__name__)
bcrypt = Bcrypt(app)
modus = Modus(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://localhost/learn-auth'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET KEY') or 'super secret' # fix this
login_manager = LoginManager()
login_manager.init_app(app)
db = SQLAlchemy(app)

from project.users.views import users_blueprint
from project.users.models import User

app.register_blueprint(users_blueprint, url_prefix='/users')

login_manager.login_view = "users.login"
login_manager.login_message = "Please log in!"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)             # WHAT DOES THIS MEAN??
