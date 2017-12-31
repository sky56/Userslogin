from flask import Flask, render_template, request, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.config['SECRET_KEY'] = "Thisisasecret"
app.config['SQLALCHEMY_DATABASE_URI']='postgresql://llqbzlgxovchpg:c7e106cf113b9715b479cfa61f4113b67f5ad3ce101f66916403a67bf5f7fd7f@ec2-54-235-219-113.compute-1.amazonaws.com/dcgpnv24p65rk7'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String())
    email = db.Column(db.String(),unique=True)
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/signup",methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        form_name = request.form["name"]
        form_email = request.form["email"].lower()
        form_password = request.form["password"]
        form_password_again = request.form["password_again"]
        hashed_password = generate_password_hash(form_password,method='sha256')
        if form_password != form_password_again:
            error = "Passwords do not match"
            return render_template("signup.html",error=error)
        elif User.query.filter_by(email=form_email).count() > 0:
            error = "User Already exists. Continue to Login!"
            return render_template("signup.html",error=error)
        else:
            new_user = User(name=form_name, email=form_email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            message = "User has been successfully created. Continue to login!"
            return render_template("signup.html",message=message)
    return render_template("signup.html")

@app.route("/login",methods=['POST','GET'])
def login():
    if request.method=='POST':
        form_email = request.form["email"].lower()
        form_password = request.form["password"]
        user = User.query.filter_by(email=form_email).first()
        if user and check_password_hash(user.password,form_password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            error = "Invalid Username/Password Combination"
            return render_template("login.html",error=error)
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/")
@login_required
def home():
    user = current_user.name
    return render_template("index.html",user=user)

if __name__ == '__main__':
    app.run()
