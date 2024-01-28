from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Post, Comment

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'key'
db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'


class UserForm(FlaskForm):
    username = StringField("Ім'я користувача")
    password = PasswordField("Пароль")
    submit = SubmitField("Зареєструватися")


class LoginForm(FlaskForm):
    username = StringField("Ім'я користувача")
    password = PasswordField("Пароль")
    submit = SubmitField("Увійти")


class PostForm(FlaskForm):
    title = StringField("Заголовок")
    content = TextAreaField("Контент")
    submit = SubmitField("Опублікувати")


class CommentForm(FlaskForm):
    text = TextAreaField("Коментар")
    submit = SubmitField("Додати коментар")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    posts = Post.query.all()
    return render_template('index.html', posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = UserForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('The registration was successful!')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def post_detail(post_id):
    post = Post.query.get(post_id)
    comments = Comment.query.filter_by(post_id=post_id).all()
    print(post.content)
    form = CommentForm()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            text = form.text.data
            new_comment = Comment(text=text, user_id=current_user.id, post_id=post_id)
            db.session.add(new_comment)
            db.session.commit()
            flash('Your comment was successfuly added')
            return redirect(url_for('post_detail', post_id=post_id))
        else:
            flash('Incorrect name or password')
            return redirect(url_for('login'))
    return render_template('post_details.html', post=post, comments=comments, form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=True)
            flash('You have joined your account', 'success')
            return redirect(url_for('index'))
        else:
            flash('Incorrect name or password', 'danger')
    return render_template('login.html', form=form)


@app.route('/add_post', methods=['GET', 'POST'])
@login_required
def add_post():
    form = PostForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        new_post = Post(title=title, content=content, user_id=current_user.id)
        db.session.add(new_post)
        db.session.commit()
        flash('TNew post was added', 'success')
        return redirect(url_for('index'))
    return render_template('add_post.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
