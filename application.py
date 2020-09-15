import os
from datetime import datetime
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd
'''

personal touch: added few requirments for markin password
see register function

'''
# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    data1 = db.execute("select symbol,sum(share) as share,bs from transactions where id = :n group by symbol,bs", n = session["user_id"])
    sum = 0
    add = {}
    for j in data1:
        if j["symbol"] not in add: add[j["symbol"]] = 0
        if j["bs"] == False:
            add[j["symbol"]] += j["share"]
        else:
            add[j["symbol"]] += -1* j["share"]
    data = db.execute("select distinct(symbol) from transactions where id = :n", n = session["user_id"])
    meta = db.execute("select cash from users where id = :n", n = session["user_id"])
    for i in data:
        i["share"] = add[i["symbol"]]
        temp = lookup(i["symbol"])
        i["name"] = temp["name"]
        i["price"] = round(temp["price"],2)
        i["total"] = round(i["price"]*add[i["symbol"]],2)
        sum += i["total"]
    cash = meta[0]["cash"]
    total = sum+ cash
    for i in data:
        if i["share"] == 0:
            data.remove(i)
    return render_template("index.html",data = data,cash= round(cash,2), total = round(total,2))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        if not symbol:
            return apology("Invalid Symbol",400)
        elif not shares:
            return apology("Missing Shares", 400)
        check = lookup(symbol)
        if check == None:
            return apology("Invalid Symbol",400)
        price = check["price"] * float(shares)
        data = db.execute("select * from users where id = :n", n = session["user_id"])
        data = data[0]
        if data["cash"] < price:
            return apology("Can't Afford",400)
        else:
            db.execute("update users set cash = :cash where id = :n", cash = data["cash"]-price, n = session["user_id"] )
            now = datetime.now()
            db.execute("insert into transactions values(:n,:sym,:name,:share,:price,:time,:b)",n = session["user_id"],sym = symbol.upper(),name = check["name"],share = shares,price = round(check["price"],2),time = now, b = False)
            return redirect("/")
    else:
        return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    data = db.execute("select symbol, share, price,datetime,bs from transactions where id = :n order by datetime ", n = session["user_id"])
    for i in data:
        if i["bs"] == False:
            i["process"] = "Bought"
        else:
            i["process"]= "Sold"
    return render_template("history.html", data=data)


@app.route("/login", methods=["GET", "POST"])
def login(username = "", password = ""):
    """Log user in"""
    # Forget any user_id
    session.clear()
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username") and username == "":
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password") and password == "" :
            return apology("must provide password", 403)
        if username == "":
            username = request.form.get("username")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=username)
        if password == "":
            password = request.form.get("password")
        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"],password):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    s = ""
    """Get stock quote."""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("Invalid Symbol", 400)
        symbol = request.form.get("symbol")
        check = lookup(symbol)
        if check == None:
            return apology("Invalid symbol", 400)
        s = "A share of "+ check["name"]+ " (" + check["symbol"] + ") costs $" + str(round(check["price"],2))
        return render_template("quote.html", check = s)
    else:
        return render_template("quote.html", check = s)


@app.route("/register", methods=["GET", "POST"])
def register():
    exist = 0
    if request.method == "POST":
        if not request.form.get("rusername"):
            return apology("must provide username", 403)
        elif not request.form.get("rpassword"):
            return apology("must provide password",403)
        elif not request.form.get("rpassword") == request.form.get("rretype"):
            return apology("Password does not match,",400)
        username = request.form.get("rusername")
        preexist = db.execute("SELECT username FROM users where username = :name", name = username)
        password = request.form.get("rpassword")
        if len(preexist) == 1:
            exist = 1
            return render_template("register.html", exist = exist)

        #final touch addin requirements to password
        elif len(password) < 4:
            exist = 2
            return render_template("register.html", exist = exist)
        elif password.isalpha():
            exist = 3
            return render_template("register.html", exist = exist)
        elif password == username:
            exist = 4
            return render_template("register.html", exist = exist)
        else:
            db.execute("Insert into users(username , hash) values (:name,:hashed)", name= username, hashed = generate_password_hash(password))
            return login(username,password)
    else:
        return render_template("register.html", exist = exist)





@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        if not symbol:
            return apology("Invalid Symbol",400)
        elif not shares:
            return apology("Missing Shares", 400)
        check = lookup(symbol)
        if check == None:
            return apology("Invalid Symbol",400)
        price = check["price"] * float(shares)
        data = db.execute("select sum(share) as share from transactions where id = :n and symbol = :sym ", n = session["user_id"],sym = symbol.upper())
        if len(data)== 0:
            return apology("Does not have requested shares", 400)
        hshares = data[0]["share"]
        if int(shares) > int(hshares):
            return apology("you have less shares", 400)
        meta = db.execute("select * from users where id = :n", n = session["user_id"])
        db.execute("update users set cash = :cash where id = :n", cash = meta[0]["cash"]+price, n = session["user_id"] )
        now = datetime.now()
        db.execute("insert into transactions values(:n,:sym,:name,:share,:price,:time, :b)",n = session["user_id"],sym = symbol.upper(),name = check["name"],share = shares,price = round(check["price"],2),time = now, b= True)
        return redirect("/")
    else:
        return render_template("sell.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
