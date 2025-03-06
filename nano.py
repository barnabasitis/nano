from flask import *
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms.validators import *
from wtforms import *
from flask_bootstrap import Bootstrap
from flask_login import *
from functools import wraps
from flask_pagedown import PageDown
from flask_pagedown.fields import PageDownField
from markdown import markdown
import bleach
from flask_httpauth import HTTPBasicAuth
from datetime import datetime
from flask_moment import Moment


app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///nano.db"
db = SQLAlchemy(app)
app.secret_key = "566gffr56uhsh7"
bootstrap = Bootstrap(app)
login_manager = LoginManager(app)
pagedown = PageDown(app)
auth = HTTPBasicAuth(app)
moment = Moment(app)


class RegistrationForm(FlaskForm):
	username = StringField("Username", validators=[DataRequired()])
	email = StringField("Email Address", validators=[DataRequired()])
	password = PasswordField("Password", validators=[EqualTo("comfirm_password", message="Password mismatch")])
	comfirm_password = PasswordField("Comfirm Pasaword")
	submit = SubmitField("Register")


class LoginForm(FlaskForm):
	username = StringField("Username", validators=[DataRequired()])
	password = PasswordField("Password")
	submit = SubmitField("Login")


class AssignRoleForm(FlaskForm):
	role = SelectField("Select Role", choices=["Moderator", "Editor"])
	submit = SubmitField("Assign")


class UsernameSearchForm(FlaskForm):
	text = StringField("Search text")
	submit = SubmitField("Search")


class PostForm(FlaskForm):
	title = StringField("Title", validators=[DataRequired()])
	body = PageDownField("Post Body")
	submit = SubmitField("Post")


class CommentForm(FlaskForm):
	text = TextAreaField("Write comment")
	submit = SubmitField("add")


class ReplyForm(FlaskForm):
	text = TextAreaField("Write a reply")
	submit = SubmitField("reply")


class SearchForm(FlaskForm):
	text = StringField("Search")
	submit = SubmitField("Search")


class Follow(db.Model):
	follower_id = db.Column(db.Integer, db.ForeignKey("users.id"), primary_key=True)
	followed_id = db.Column(db.Integer, db.ForeignKey("users.id"), primary_key=True)
	timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class Users(UserMixin, db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String, nullable=False, unique=True)
	email = db.Column(db.String, nullable=False, unique=True)
	password = db.Column(db.String, nullable=False)
	role = db.Column(db.String, default="User")
	posts = db.relationship("Posts", backref="author", lazy="dynamic")
	comments = db.relationship("Comments", backref="author", lazy="dynamic")
	replies = db.relationship("CommentReplies", backref="author", lazy="dynamic")
	
	followed = db.relationship("Follow", foreign_keys=[Follow.follower_id], backref=db.backref("follower", lazy="joined"), lazy="dynamic", cascade="all, delete-orphan")
	
	followers = db.relationship("Follow", foreign_keys=[Follow.followed_id], backref=db.backref("followed", lazy="joined"), lazy="dynamic", cascade="all, delete-orphan")
	
	
	def __init__(self, *args, **kwargs):
		super().__init__(**kwargs)
		if self.email == "iorsengeb@gmail.com":
			self.role = "Admin"
		
	def followed_posts(self):
		posts = Posts.query.join(Follow, (Follow.followed_id == Posts.user_id)).filter(Follow.follower_id==self.id)
		data = [
			{
				"id": post.id,
			"self_url": url_for("view_post", post_id=post.id),
			"title": post.title,
			'body': post.body,
			"body_html": post.body_html,
			"timestamp": post.timestamp.strftime("%d %b, %Y %I:%M %p"),
			"views": post.views,
			"author": post.author.username,
			"author_url": url_for("profile", username=post.author.username),
			"comments_count": post.comments.count(),
			"comments": [
				{
				"id": c.id,
				"text": c.text,
				"timestamp": c.timestamp,
				"author": c.author.username,
				"author_url": url_for("profile", username=c.author.username),
				"comm_url": url_for("view_comment", comment_id=c.id)
			}for c in post.comments],
			}
			for post in posts
		]
		return data
	
	def verify_password(self, psw):
		return self.password == psw
	
	def is_author(self, p_c):
		if p_c.author == self:
			return True
	
	def follow(self, user):
		if not self.is_following(user):
			f = Follow(follower=self, followed=user)
			db.session.add(f)
	
	def unfollow(self, user):
		f = self.followed.filter_by(followed_id=user.id).first()
		if f:
			db.session.delete(f)
	
	def is_following(self, user):
		if user is None:
			return False
		return self.followed.filter_by(followed_id=user.id).first() is not None
	
	def to_dict(self):
		data = {
			"id": self.id,
			"username": self.username,
			"email": self.email,
			"role": self.role,
			"followers_count": self.followers.count(),
			"followed_count": self.followed.count(),
			"posts": [{
				"id": post.id,
				"title": post.title,
				"body": post.body,
				"body_html": post.body_html,
				"views": post.views,
				"comments_count": post.comments.count(),
				"post_url": url_for("view_post", post_id=post.id),
				"timestamp": post.timestamp.strftime("%d %b, %Y %I:%M %p"),
				"author": post.author.username,
				"author_url": url_for("profile", username=post.author.username)
			} for post in self.posts],
			"self_url": url_for("user", username=self.username)
		}
		return data


class Posts(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String, nullable=False)
	body = db.Column(db.Text)
	body_html = db.Column(db.Text)
	timestamp = db.Column(db.DateTime, default=datetime.utcnow())
	views = db.Column(db.Integer, default=0)
	user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
	comments = db.relationship("Comments", backref="post",lazy="dynamic")
	
	def __init__(self, *args, **kwargs):
		super().__init__(**kwargs)
	
	def to_json(self):
		data = {
			"id": self.id,
			"self_url": url_for("view_post", post_id=self.id),
			"title": self.title,
			'body': self.body,
			"body_html": self.body_html,
			"timestamp": self.timestamp.strftime("%d %b, %Y %I:%M %p"),
			"views": self.views,
			"author": self.author.username,
			"author_url": url_for("profile", username=self.author.username),
			"comments_count": self.comments.count(),
			"comments": [
				{
				"id": c.id,
				"text": c.text,
				"timestamp": c.timestamp,
				"author": c.author.username,
				"author_url": url_for("profile", username=c.author.username),
				"comm_url": url_for("view_comment", comment_id=c.id)
				}
				for c in self.comments
			]
		}
		return data

	@staticmethod
	def on_change_body(target, value, oldvalue, initiator):
		target.body_html = bleach.linkify(
			bleach.clean(
				markdown(
				value,
				output_format="html",
				),
				tags=["a", "h1", "strong", "h2", "h3", "h4", "h5", "p"],
				strip=True
			)
		)
		
	def add_view(self):
		self.views += 1
		db.session.add(self)


db.event.listen(Posts.body, "set", Posts.on_change_body)



class Comments(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	text = db.Column(db.Text, nullable=False)
	timestamp = db.Column(db.DateTime, default=datetime.utcnow())
	post_id = db.Column(db.Integer, db.ForeignKey("posts.id"))
	user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
	replies = db.relationship("CommentReplies", backref="comment", lazy="dynamic")
	
	def __init__(self, *args, **kwargs):
		super().__init__(**kwargs)
	
	def to_json(self):
		data = {
			"id": self.id,
			"text": self.text,
			"timestamp": self.timestamp,
			"post": self.post.id,
			"author": self.author.username,
			"replies_count": self.replies.count(),
			"replies": [{
				"id": reply.id,
				"text": reply.text,
				"author": reply.author.username
			} for reply in self.replies],
			"author_url": url_for("profile", username=self.author.username),
			"self_url": url_for("view_comment", comment_id=self.id)
		}
		return data


class CommentReplies(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	text = db.Column(db.Text)
	comment_id = db.Column(db.Integer, db.ForeignKey("comments.id"))
	user_id = db.Column(db.Integer, db.ForeignKey("users.id"))



with app.app_context():
	db.create_all()


def admin_required(f):
	@wraps(f)
	def deco(*args, **kwargs):
		if current_user.is_authenticated:
			if not current_user.role == "Admin":
				abort(403)
		return f(*args, **kwargs)
	return deco


def moderator_required(f):
	@wraps(f)
	def deco(*args, **kwargs):
		if current_user.is_authenticated:
			if not current_user.role in ["Admin", "Moderator"]:
				abort(403)
		return f(*args, **kwargs)
	return deco


@login_manager.user_loader
def load_user(user_id):
	return Users.query.get_or_404(user_id)


@app.route("/")
def index():
	posts = Posts.query.all()
	search_form = SearchForm()
	return render_template("index.html", posts=posts, search_form=search_form)


@app.route("/login", methods=["POST", "GET"])
def login():
	if current_user.is_authenticated:
		return redirect(url_for("index"))
	login_form = LoginForm()
	if login_form.validate_on_submit():
		user = Users.query.filter_by(username=login_form.username.data).first()
		if user is not None and user.verify_password(login_form.password.data):
			login_user(user)
			return redirect(url_for("index"))
	return render_template("login.html", login_form=login_form)


@app.route("/register", methods=["POST", "GET"])
def register():
	if current_user.is_authenticated:
		return redirect(url_for("index"))
	register_form = RegistrationForm()
	if register_form.validate_on_submit():
		user = Users(
			username=register_form.username.data,
			email=register_form.email.data,
			password=register_form.password.data
		)
		db.session.add(user)
		db.session.commit()
		login_user(user)
		return redirect(url_for("index"))
	return render_template("register.html", register_form=register_form)


@app.route("/assign_role/<username>", methods=["POST", "GET"])
@login_required
@admin_required
def assign_role(username):
	role_form = AssignRoleForm()
	user = Users.query.filter_by(username=username).first()
	if role_form.validate_on_submit():
		if user is not None:
			user.role = role_form.role.data
			db.session.add(user)
		db.session.commit()
		return redirect(url_for("manage_roles"))
	return render_template("assign_role.html", role_form=role_form, user=user)


@app.route("/manage_roles")
@login_required
@admin_required
def manage_roles():
	users = Users.query.all()
	form = UsernameSearchForm()
	return render_template("mange_roles.html", users=users)

@app.route("/username_search")
@login_required
@admin_required
def username_search():
	query = request.args.get("srch")
	
	if not query:
		return jsonify({"Error": "No query provided"})
	
	search = Users.query.filter((Users.username.contains(query))).all()
	return jsonify([{"id": user.id, "url": url_for("assign_role", username=user.username), "username": user.username, "role": user.role} for user in search])


@app.route("/search")
@login_required
def search():
	query = request.args.get("search_text")
	if not query:
		return jsonify({"Error": "Null"})
	search_result = Posts.query.filter((Posts.title.contains(query)))
	s = jsonify([
		{"id": post.id,
			"title": post.title,
			"body_html": post.body_html,
			"author": post.author.username,
			"author_url": url_for("profile", username=post.author.username),
			"self_url": url_for("view_post", post_id=post.id),
			"comments_count": post.comments.count(),
			"views": post.views
		} for post in search_result
	])
	return s if s else {"err": "No matching results"}


@app.route("/create_post", methods=["GET", "POST"])
@login_required
def create_post():
	post_form = PostForm()
	if post_form.validate_on_submit():
		post = Posts(
			title=post_form.title.data,
			body=post_form.body.data,
			author=Users.query.filter_by(username=current_user.username).first()
		)
		db.session.add(post)
		db.session.commit()
		return redirect(url_for("index"))
	return render_template("create_post.html", post_form=post_form)



@app.route("/user/<username>", methods=["GET"])
@login_required
def user(username):
	user = Users.query.filter_by(username=username).first().to_dict()
	return jsonify(user)


@app.route("/profile/<username>")
@login_required
def profile(username):
	user = Users.query.filter_by(username=username).first()
	return render_template("profile.html", user=user)


@app.route("/follow/<username>")
@login_required
def follow(username):
	user = Users.query.filter_by(username=username).first()
	if not current_user.is_following(user):
		current_user.follow(user)
	db.session.commit()
	return redirect(url_for("profile", username=user.username))


@app.route('/unfollow/<username>')
@login_required
def unfollow_(username):
	user = Users.query.filter_by(username=username).first()
	if user is None:
		return False
	if current_user.is_following(user):
		current_user.unfollow(user)
	db.session.commit()
	return redirect(url_for("profile", username=user.username))


@app.route("/post/<int:post_id>")
def post(post_id):
	return Posts.query.get_or_404(post_id).to_json()


@app.route("/posts")
def posts():
	posts = Posts.query.all()
	return jsonify([post.to_json() for post in posts])


@app.route("/followed_posts")
@login_required
def get_followed_posts():
	return current_user.followed_posts() if current_user.followed_posts() else {"err": "Follow users to see there posts"}


@app.route("/user_followers/<username>")
@login_required
def get_user_followers(username):
	user = Users.query.filter_by(username=username).first()
	
	return ""


@app.route("/view_post/<int:post_id>", methods=["POST", "GET"])
def view_post(post_id):
	post = Posts.query.get_or_404(post_id)
	post.add_view()
	form = CommentForm()
	if form.validate_on_submit():
		comment = Comments(
			text=form.text.data,
			author=Users.query.filter_by(username=current_user.username).first(),
			post=post,
		)
		db.session.add(comment)
		db.session.commit()
		return redirect(url_for("view_post", post_id=post.id))
	return render_template("view_post.html", post=post, form=form)


@app.route("/comment/<int:comment_id>")
def comment(comment_id):
	return Comments.query.get_or_404(comment_id).to_json()


@app.route("/view_comment/<int:comment_id>", methods=["POST", "GET"])
def view_comment(comment_id):
	comment = Comments.query.get_or_404(comment_id)
	form = ReplyForm()
	if form.validate_on_submit():
		reply = CommentReplies(
			text=form.text.data,
			author=Users.query.filter_by(username=current_user.username).first(),
			comment=comment
		)
		db.session.add(reply)
		db.session.commit()
		return redirect(url_for("view_comment", comment_id=comment.id))
	return render_template("view_comment.html", comment=comment, form=form)


@app.route("/moderate")
@login_required
@moderator_required
def moderate():
	return "This is the moderator route"


@app.route("/logout")
def logout():
	logout_user()
	return redirect(url_for("index"))


app.run()