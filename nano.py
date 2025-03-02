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


class Users(UserMixin, db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String, nullable=False, unique=True)
	email = db.Column(db.String, nullable=False, unique=True)
	password = db.Column(db.String, nullable=False)
	role = db.Column(db.String, default="User")
	posts = db.relationship("Posts", backref="author", lazy="dynamic")
	
	def __init__(self, *args, **kwargs):
		super().__init__(**kwargs)
		if self.email == "iorsengeb@gmail.com":
			self.role = "Admin"
	
	def verify_password(self, psw):
		return self.password == psw
	
	def to_dict(self):
		data = {
			"id": self.id,
			"username": self.username,
			"email": self.email,
			"role": self.role,
			"posts": [{
				"id": post.id,
				"title": post.title,
				"body": post.body,
				"body_html": post.body_html,
				"timestamp": moment(post.timestamp).fromNow(),
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
	user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
	
	def __init__(self, *args, **kwargs):
		super().__init__(**kwargs)
	
	def to_json(self):
		data = {
			"self_url": url_for("post", post_id=self.id),
			"title": self.title,
			'body': self.body,
			"body_html": self.body_html,
			"timestamp": moment(self.timestamp).fromNow(),
			"author": self.author.username,
			"author_url": url_for("profile", username=self.author.username)
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
				tags=["a", "h1"],
				strip=True
			)
		)


db.event.listen(Posts.body, "set", Posts.on_change_body)



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
	return render_template("index.html", posts=posts)


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
	return jsonify([{"id": user.id, "url": f"/assign_role/{user.username}", "username": user.username} for user in search])


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


@app.route("/post/<int:post_id>")
@login_required
def post(post_id):
	return Posts.query.get_or_404(post_id).to_json()


@app.route("/posts")
def posts():
	posts = Posts.query.all()
	return jsonify([post.to_json() for post in posts])


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