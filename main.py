from flask import Flask, render_template, redirect, url_for, request, abort, flash
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import Integer, String, Text, ForeignKey
from flask_ckeditor import CKEditor
from flask_ckeditor.utils import cleanify
from datetime import date
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
import smtplib
from email.message import EmailMessage
import os
import hashlib
from urllib.parse import urlencode
from dotenv import load_dotenv

load_dotenv()

user_email = os.environ.get('USER_EMAIL')
user_password = os.environ.get('USER_PASSWORD')


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
Bootstrap5(app)
ckeditor = CKEditor(app)

def gravatar_url(email: str | None, size: int = 100, rating: str = "g", default: str = "retro", force_default: bool = False) -> str:
    """
    Build a Gravatar URL from an email. Safe for None/empty emails.
    Gravatar spec: MD5 hash of the trimmed, lowercased email.
    """
    normalized = (email or "").strip().lower().encode("utf-8")
    email_hash = hashlib.md5(normalized).hexdigest()
    base = "https://www.gravatar.com/avatar/"
    params = {"s": size, "r": rating, "d": default}
    if force_default:
        params["f"] = "y"
    return f"{base}{email_hash}?{urlencode(params)}"


# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.context_processor
def inject_gravatar():
    return dict(gravatar_url=gravatar_url)


@app.context_processor
def inject_current_year():
    return {"current_year": date.today().year}


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_URI')
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE TABLE
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)

    # Relationship to User (one author per post)
    author: Mapped["User"] = relationship("User", back_populates="posts")

    img_url: Mapped[str] = mapped_column(String(250), nullable=False)

    # Relationship to Comment (many comments per post)
    comments: Mapped[list["Comment"]] = relationship("Comment", back_populates="parent_post", cascade="all, delete-orphan")


# TODO: Create a User table for all your registered users.
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(250), nullable=False)
    email: Mapped[str] = mapped_column(String(250), nullable=False, unique=True)
    password: Mapped[str] = mapped_column(String(250), nullable=False)

    # Reverse relationships
    posts: Mapped[list["BlogPost"]] = relationship("BlogPost", back_populates="author", cascade="all, delete-orphan")
    comments: Mapped[list["Comment"]] = relationship("Comment", back_populates="comment_author", cascade="all, delete-orphan")

class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    post_id: Mapped[int] = mapped_column(ForeignKey("blog_posts.id"))
    text: Mapped[str] = mapped_column(String(500), nullable=False)

    # Relationships to User and BlogPost
    comment_author: Mapped["User"] = relationship("User", back_populates="comments")
    parent_post: Mapped["BlogPost"] = relationship("BlogPost", back_populates="comments")


with app.app_context():
    db.create_all()



# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        email = register_form.email.data
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        if user:
            flash("Email address already exists")
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(password=register_form.password.data, method='pbkdf2:sha256', salt_length=8)
        new_user = User(email=register_form.email.data, name=register_form.name.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=register_form)


# TODO: Retrieve a user from the database based on their email.
@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.password.data

        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()

        if not user:
            flash("This email does not exist, please try again or sign up!")
            return redirect(url_for('register'))
        elif not check_password_hash(user.password, password):
            flash("Incorrect password, please try again!")
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    # TODO: Query the database for all the posts. Convert the data to a python list.
    results = db.session.execute(db.select(BlogPost))
    posts = results.scalars().all()
    return render_template("index.html", all_posts=posts)


# TODO: Add a route so that you can click on individual posts.
@app.route('/<int:post_id>', methods=['GET', 'POST'])
def show_post(post_id):
    # TODO: Retrieve a BlogPost from the database based on the post_id
    requested_post = db.get_or_404(BlogPost, post_id)
    comment_form = CommentForm()

    results = db.session.execute(db.select(Comment).where(Comment.post_id == post_id))
    all_comments = results.scalars().all()

    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment on a post.")
            return redirect(url_for('login'))

        new_comment = Comment(
            author_id=current_user.id,
            post_id=requested_post.id,
            text=cleanify(comment_form.comment_text.data))
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))
    return render_template("post.html", post=requested_post, form=comment_form, current_user=current_user, comments=all_comments)


# TODO: add_new_post() to create a new blog post
@app.route('/new-post', methods=['GET', 'POST'])
@admin_only
@login_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.title.data,
            author=current_user,
            img_url=form.img_url.data,
            body=cleanify(form.body.data),
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    return render_template('make-post.html', form=form)


# TODO: edit_post() to change an existing blog post
@app.route('/edit-post/<int:post_id>', methods=['GET', 'POST'])
@admin_only
@login_required
def edit_post(post_id):
    post_to_edit = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(title=post_to_edit.title,
                               subtitle=post_to_edit.subtitle,
                               img_url=post_to_edit.img_url,
                               author=post_to_edit.author,
                               body=post_to_edit.body
                               )
    if edit_form.validate_on_submit():
        post_to_edit.title = edit_form.title.data
        post_to_edit.subtitle = edit_form.subtitle.data
        post_to_edit.img_url = edit_form.img_url.data
        post_to_edit.body = edit_form.body.data
        post_to_edit.img_url = edit_form.img_url.data
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))
    return render_template('make-post.html', form=edit_form, is_edit=True)


# TODO: delete_post() to remove a blog post from the database
@app.route('/delete-post/<int:post_id>', methods=['GET', 'POST'])
@admin_only
@login_required
def delete_post(post_id):
    post_to_delete = db.session.get(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=['GET', 'POST'])
def contact():
    message_sent = False
    if request.method == 'POST':
        msg = EmailMessage()
        msg["From"] = user_email
        msg["To"] = "linkmunirih@gmail.com"
        msg["Subject"] = "Message From Blog User"
        msg.set_content(f"Name: {request.form.get('name')}\n"
                        f"Email Address: {request.form.get('email')}\n"
                        f"Phone Number: {request.form.get('phone')}\n"
                        f"Message:\n{request.form.get('message')}"
        )
        try:
            with smtplib.SMTP('smtp.gmail.com', 587) as connection:
                connection.starttls()
                connection.login(user=user_email, password=user_password)
                connection.send_message(msg)
                message_sent = True
            print("Email sent!")
        except smtplib.SMTPAuthenticationError as e:
            print("Authentication failed. If you're using Gmail, use an App Password (2FA enabled).")
            raise
        except Exception as e:
            print(f"Failed to send email: {e}")
    return render_template("contact.html", msg_sent=message_sent)


@app.route('/delete_comment/<int:comment_id>', methods=['GET', 'POST'])
def delete_comment(comment_id):
    comment_to_delete = db.get_or_404(Comment, comment_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=False)
