from flask import render_template, redirect, request, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from . import auth
from .. import db
from ..models import User
from .forms import LoginForm, RegistrationForm
from ..email import send_email


@auth.before_app_request  # 註冊成全域的裝飾器
def before_request():  # 如果使用者有登入下的判斷
    if current_user.is_authenticated \
            and not current_user.confirmed \
            and request.endpoint \
            and request.blueprint != 'auth' \
            and request.endpoint != 'static':
        return redirect(url_for('auth.unconfirmed'))


@auth.route('/unconfirmed')
def unconfirmed(): # 帳號確認頁面
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():  # 若表單被送出
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)  # 幫使用者session紀錄已登入
            next = request.args.get('next')
            if next is None or not next.startswith('/'): # 功用不明
                next = url_for('main.index')
            return redirect(next)
        flash('Invalid email or password')
    return render_template('auth/login.html',form=form)


@auth.route('/logout')  # 登出路由
@login_required
def logout():
    logout_user() # 重置使用者session 移除登入資訊
    flash('You have been logged out.')
    return redirect(url_for('main.index'))


@auth.route('/register', methods=['GET', 'POST'])
def register():  # 註冊路由
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data.lower(),
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token() # 註冊成功後將user token 放入模板寄信
        send_email(user.email, 'Confirm Your Account',
                   'auth/email/confirm', user=user, token=token)
        flash('A confirmation email has been sent to you by email.')
        return redirect(url_for('auth.login'))  # 轉跳到登入頁面
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:  # 若登入就轉跳到首頁  避免按下很多次確認token而產生沒必要的工作
        return redirect(url_for('main.index'))
    if current_user.confirm(token):  # 若token正確 會由models更改確認狀態 由此處送出db.session
        db.session.commit()
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))


@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm Your Account',
               'auth/email/confirm', user=current_user, token=token)
    flash('A new confirmation email has been sent to you by email.')
    return redirect(url_for('main.index'))

# 測試保護路由
@auth.route('/secret')
@login_required
def secret():
    return 'Only authenticated users are allowed!'

