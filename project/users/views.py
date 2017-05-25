from flask import redirect, render_template, request, url_for, Blueprint, flash
from project.users.forms import UserForm, EditUserForm
from project.users.models import User
from project import db,bcrypt
from flask_login import login_user, logout_user, current_user, login_required
from functools import wraps
from sqlalchemy.exc import IntegrityError


users_blueprint = Blueprint(
    'users',
    __name__,
    template_folder='templates'
)


def ensure_correct_user(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if kwargs.get('id') != current_user.id:
            flash("Not Authorized")
            return redirect(url_for('users.welcome'))
        return fn(*args, **kwargs)
    return wrapper

@users_blueprint.route('/signup', methods=['GET', 'POST'])
def signup():
    form = UserForm(request.form)
    if form.validate_on_submit():                   # vs. .validate(), .validate_on_submit() checks post/patch/delete + validate
        try:
            new_user = User(form.data['username'], form.data['password'])
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError as e:                 # without this block, the server would crash when the db complained
            flash('Username already taken')
            return render_template('signup.html', form=form)
        flash('User created, please login to continue')
        return redirect(url_for('users.login'))
    return render_template('signup.html', form=form)

@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    form = UserForm(request.form)
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.data['username']).first()
        if user and bcrypt.check_password_hash(user.password, form.data['password']):
            flash('You have successfully logged in!')
            # session['user_id'] = user.id
            login_user(user)
            return redirect(url_for('users.welcome'))
        flash('Invalid credentials')
    return render_template('login.html', form=form)

@users_blueprint.route('/welcome')
@login_required
def welcome():
    return render_template('welcome.html')

@users_blueprint.route('/<int:id>/edit')
@login_required
def edit(id):
    form = EditUserForm(request.form)
    return render_template('edit.html', form=form, id=id)


@users_blueprint.route('/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
@login_required
@ensure_correct_user
def show(id):
    user = User.query.get(id)
    if request.method == b'PATCH':
        form = EditUserForm(request.form)
        # from IPython import embed; embed()
        user.username = request.form['username']

        if request.form['current_password'] and bcrypt.check_password_hash(user.password, request.form['current_password']):
            if request.form['new_password'] == request.form['confirm_password']:
                user.password = bcrypt.generate_password_hash(request.form['new_password']).decode('UTF-8') 
                db.session.add(user)
                db.session.commit()
                return redirect(url_for('users.welcome'))
            flash('Invalid credentials.')
            return redirect(url_for('users.edit', id=id))
    if request.method == b'DELETE':
        db.session.delete(user)
        db.session.commit()
        return redirect(url_for('users.signup'))
    return render_template('show.html', user=user)

@users_blueprint.route('/logout')
@login_required
def logout():
    flash("You're now logged out!")
    logout_user()
    return redirect(url_for('users.login'))