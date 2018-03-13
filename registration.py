from flask import Flask, request, redirect, render_template, session, flash
from mysqlconnection import MySQLConnector
import re
import bcrypt

app = Flask(__name__)
app.secret_key = 'Secret'
mysql = MySQLConnector(app, 'theWall')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
NAME_REGEX = re.compile(r'^[a-zA-Z]+$')

@app.route("/")
def index():
    query = "SELECT * FROM users"
    users = mysql.query_db(query)
    # print request.form['emailAddress']
    return render_template('index.html', users=users)


@app.route("/register", methods=['POST'])
def register():
    OK = True

    if len(request.form['first']) < 2:
        flash("First Name must be at least two characters")
        OK = False
    elif not re.match(NAME_REGEX, request.form['first']):
        flash('Name cannot contain numbers')
        OK = False

    if len(request.form['last']) < 2:
        flash("Last Name must be at least two characters")
        OK = False
    elif not re.match(NAME_REGEX, request.form['last']):
        flash('Name cannot contain numbers')
        OK = False

    if len(request.form['email']) == 0:
        flash("Email required")
        OK = False
    elif not re.match(EMAIL_REGEX, request.form['email']):
        flash('Invalid Email')
        OK = False
    else:
        email_list = mysql.query_db("SELECT * FROM users WHERE email = :email", request.form)
        if len(email_list) > 0:
            flash("Email has been used already")

    if len(request.form['password']) < 1:
        flash("password required")
        OK = False
    elif len(request.form['password']) < 8:
        flash("Your password must be at least eight characters long")
        OK = False
    if (request.form['password'] != request.form['confirm']):
        flash("Password confirmation does not match entered password")
        OK = False

    if OK:
        data = {
            "first": request.form['first'],
            "last": request.form['last'],
            "email": request.form['email'],
            # "password": request.form["password"]
            "password": bcrypt.hashpw(request.form["password"].encode(), bcrypt.gensalt())
        }
        query = "INSERT INTO users (first, last, email, password, created_at, updated_at) VALUES (:first, :last, :email, :password, NOW(), NOW());"
        user_id = mysql.query_db(query, data) #request.form
        # session['username'] = request.form['first']+' '+request.form['last']
        # mysql.query_db(query, data) #request.form
        return redirect("/confirm")
    else:
        return redirect('/')


@app.route("/login", methods=['POST'])
def login():
    OK = True

    if len(request.form['email']) == 0:
        flash("Email required")
        OK = False
    elif not re.match(EMAIL_REGEX, request.form['email']):
        flash('Invalid Email')
        OK = False
    else:
        email_list = mysql.query_db(
            "SELECT * FROM users WHERE email = :email", request.form)
        if len(email_list) == 0:
            flash("Invalid email")
            OK = False

    if len(request.form['password']) < 1:
        flash("password required")
        OK = False
    elif len(request.form['password']) < 8:
        flash("Your password must be at least eight characters long")
        OK = False

    if not OK:
        return redirect("/")

    user = email_list[0]

    if bcrypt.hashpw(request.form["password"].encode(), bcrypt.gensalt()):
        session["user_id"] = user["id"]
        session["username"] = user["first"]+" "+user["last"]
        return redirect("/confirm")
    else:
        #flash errors
        return redirect('/confirm')

@app.route("/confirm")
def confirm():
    return render_template("confirmpage.html")

@app.route("/logout", methods=['POST'])
def logout():
    session.clear()
    return redirect("/")


app.run(debug=True)
