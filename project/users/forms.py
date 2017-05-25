from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired

class UserForm(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])

class EditUserForm(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    current_password = PasswordField('current password')
    new_password = PasswordField('new password')
    confirm_password = PasswordField('confirm new password')