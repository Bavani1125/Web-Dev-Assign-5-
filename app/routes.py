from flask import Blueprint, render_template, redirect, url_for, flash, request
from .forms import SignupForm, LoginForm, UpdateProfileForm, ResetPasswordForm
from .models import User
from . import db, bcrypt
from flask_login import login_user, logout_user, login_required, current_user

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return redirect(url_for('main.login'))

@main.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        answer_hashed = bcrypt.generate_password_hash(form.security_answer.data).decode('utf-8')
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_pw,
            security_question=form.security_question.data,
            security_answer=answer_hashed
        )
        db.session.add(user)
        db.session.commit()
        flash('Account created! Please login.', 'success')
        return redirect(url_for('main.login'))
    return render_template('signup.html', form=form)

@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('main.portal'))
        else:
            flash('Invalid credentials.', 'danger')
    return render_template('login.html', form=form)

@main.route('/portal')
@login_required
def portal():
    return render_template('portal.html')

@main.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.login'))

@main.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = UpdateProfileForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        if form.password.data:
            current_user.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        db.session.commit()
        flash('Profile updated!', 'success')
        return redirect(url_for('main.portal'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('profile.html', form=form)

@main.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.security_answer, form.security_answer.data):
            user.password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
            db.session.commit()
            flash('Password reset successful.', 'success')
            return redirect(url_for('main.login'))
        else:
            flash('Incorrect answer.', 'danger')
    return render_template('reset_password.html', form=form)

@main.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash("Access denied!", "danger")
        return redirect(url_for('main.portal'))
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@main.route('/admin/delete/<int:user_id>')
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash("Access denied!", "danger")
        return redirect(url_for('main.portal'))
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash("User deleted.", "info")
    return redirect(url_for('main.admin_dashboard'))
