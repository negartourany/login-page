import werkzeug.security
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Mapped, mapped_column, DeclarativeBase
from sqlalchemy import String, Integer
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user

app = Flask(__name__)


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

#  building login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(1000), nullable=False)



with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["POST", "GET"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        hashed_password = werkzeug.security.generate_password_hash(password=password, method="pbkdf2", salt_length=8)
        user = User.query.filter_by(email=email).first()
        if user:
            flash("User already exists.","error")
            return redirect(url_for("register"))
        new_user = User(
            name=name,
            email=email,
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return render_template("secrets.html", name=name)
    return render_template("register.html")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login',methods=["POST","GET"])
def login():
    email = request.form.get("email")
    password = request.form.get("password")
    user = User.query.filter_by(email=email).first()
    if request.method == "POST":
        if user:
            database_hash_pass = user.password
            hashed_pass = werkzeug.security.check_password_hash(password=password, pwhash=database_hash_pass)
            # logged_in = current_user.is_authenticated
            if password == hashed_pass:
                return redirect(url_for("secrets"))
            else:
                flash("invalid password","error")
                return redirect(url_for("login"))
        else:
            flash("This email is not registered")
            return redirect(url_for("login"))
    return render_template("login.html")

@app.context_processor
def inject_logged_in():
    return dict(logged_in=current_user.is_authenticated)
@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    print(current_user.is_authenticated)
    return redirect(url_for("home"))


@app.route('/download')
@login_required
def download():
    return send_from_directory(directory="static/files", path="cheat_sheet.pdf", as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
