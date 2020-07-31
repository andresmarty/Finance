import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

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


@app.route("/", methods=["GET"])
@login_required
def index():
    idUser = session.get("user_id")
    if "user_id" in session:
        portfolio = db.execute("SELECT * FROM portfolio p JOIN users u ON u.id = p.user_id WHERE p.user_id = :user", user = idUser);
        users = db.execute("SELECT * FROM users WHERE id = :user", user = idUser)
        suma = db.execute("SELECT SUM(sum) FROM portfolio WHERE user_id = :user", user = idUser)
        return render_template("index.html", portfolio = portfolio, users = users, suma = suma)
    return render_template("login.html")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():

    #validate if input symbol is correct
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        stock = lookup(symbol)
        shares = int(request.form.get("shares"))
        total = int(stock['price']) * int(shares)
        user = session.get("user_id")
        userCash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id = user)[0]['cash']
        rows = db.execute("SELECT * FROM portfolio WHERE user_id = :user_id and symbol = :symbol",
                        user_id = user, symbol = symbol);
        users = db.execute("SELECT * FROM users WHERE id = :user_id", user_id = user)
        portfolio = db.execute("SELECT * FROM portfolio p JOIN users u ON u.id = p.user_id WHERE p.user_id = :user", user = user);
        suma = db.execute("SELECT SUM(sum) FROM portfolio WHERE user_id = :user", user = user)

        #check if value of share exists
        if stock == None:
            return apology("Incorrect value of Stock", 403)

        #check if user has enought money
        if total > userCash:
            return apology("Not enough Money", 403)

        #CHECK IF VALUE INSERTED IS POSITIVE
        if shares < 0:
            return apology("Value must be positive", 403)

        #check if share exists
        if len(rows) >= 1:
            for s in rows:
                actualShares = s['share']
                share = int(shares)

                db.execute("UPDATE portfolio SET share = :amount, sum = :suma  WHERE user_id = :user and symbol= :symbol",
                                                            amount = (actualShares + share),  user = user , symbol = symbol, suma = (s['sum'] + (stock['price'] * shares)));
                db.execute("UPDATE users SET cash = :rest WHERE id = :user", user = user , rest = (userCash - total));

                flash('bought!')
                return render_template("index.html", users = users, portfolio = portfolio, suma = suma)


        #INSERT INTO TABLES INFORMATION OF STOCK BOUGHT
        db.execute("INSERT INTO portfolio (user_id, symbol, share, name, price, sum) VALUES (:user_id, :symbol, :amount, :name, :price, :suma)",
                                            user_id = user, symbol = stock["symbol"], amount = shares, name = stock['name'],
                                            price = stock['price'], suma = (shares * stock['price']));
        db.execute("INSERT INTO transactions (user_id, symbol, share, price) VALUES (:user_id, :symbol, :amount, :price)",
                                            user_id = user, symbol = stock["symbol"], amount = shares, price = stock['price']);

        # UPDATE MONEY AFTER TRANSACTION COMPLETED
        db.execute("UPDATE users SET cash = :rest WHERE id = :user", user = user , rest = (userCash - total))
        flash('bought!')
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    user = session.get("user_id")
    history = db.execute("SELECT * FROM transactions WHERE user_id = :user", user = user)

    return render_template("history.html", history = history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
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
    if request.method == "POST":
        symbol = request.form.get("quote")
        stock = lookup(symbol)

        # Ensure that quote exists
        if stock == None:
            return apology("No Quote Found", 403)

        return render_template("stockvalue.html", stock=stock)
    else:
        return render_template("quote.html")

@app.route("/password", methods=["GET", "POST"])
def password():

    if request.method == "POST":
        user = session.get("user_id")
        oldpassword = request.form.get("oldpassword")
        newpassword = request.form.get("newpassword")
        newpassword2 = request.form.get("newpassword2")
        datauser = db.execute("SELECT * FROM users WHERE id = :id", id = user)
        print(datauser)
        hashed = generate_password_hash(newpassword)

        # Ensure new password was submitted
        if not request.form.get("newpassword"):
            return apology("must provide username", 403)

        # Ensure new password 2 was submitted
        if not request.form.get("newpassword2"):
            return apology("must provide password", 403)

        # Ensure new oldpassword was submitted
        if not request.form.get("oldpassword"):
            return apology("must provide password", 403)

        # Ensure new password is different than the old one
        if oldpassword == newpassword or oldpassword == newpassword2:
            return apology("New password must be different", 403)

        # Check if old password is correct
        if check_password_hash(datauser[0]["hash"], oldpassword) is False:
            return apology("invalid actual password", 403)

        # Ensure new passwords match
        if newpassword != newpassword2:
            return apology("Write again the new password", 403)

        db.execute("UPDATE users SET hash = :password WHERE id = :user", password = hashed, user = user)

        flash("Password Changed")
        return redirect("/")
    else:
        return render_template("password.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    user = request.form.get("username")
    passw = request.form.get("password")
    passw2 = request.form.get("password2")
    rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 403)

        # Check password
        if (passw != passw2):
            return apology("Incorrect Password", 403)

        hashed = generate_password_hash(passw)

        # Check User in database
        if len(rows) >= 1:
            return apology("User already Exists", 403)

        # Insert Into Database USER and PASSWORD
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :password)", {"username":user, "password":hashed});

        flash('Registered!')
        return render_template("login.html")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    symbol = request.form.get("symbol")
    shares = request.form.get("shares")
    user = session.get("user_id")
    stocks = db.execute("SELECT symbol, share, sum FROM portfolio JOIN users ON users.id = portfolio.user_id WHERE id = :user_id ", user_id = user)
    selectedStock = db.execute("SELECT * FROM portfolio WHERE symbol = :symbol", symbol = symbol)
    cero = 0


    if request.method == "POST":
        stock = lookup(symbol)
        userCash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id = user)[0]['cash']

        # Check if user has enought shares to sell
        if int(shares) > int(selectedStock[0]['share']):
            return apology("not enought shares", 403)

        #CHECK IF VALUE INSERTED IS POSITIVE
        if shares < 0:
            return apology("Value must be positive", 403)

        # UPDATE SHARES IN PORTFOLIO
        db.execute("UPDATE portfolio SET share = :share, sum = :suma WHERE user_id = :user and symbol = :symbol",
        user = user , share = (selectedStock[0]['share'] - int(shares)) , symbol = symbol,
        suma = (selectedStock[0]['sum'] - (int(shares) * stock['price'])));

        # INSERT INFORMATION INTO TRANSACTIONS TABLE
        db.execute("INSERT INTO transactions (user_id, symbol, share, price) VALUES (:user_id, :symbol, :share, :price)",
                                    user_id = user, symbol = stock["symbol"], share = (cero - int(shares)), price = stock['price']);

        # UPDATE CASH IN USERS TABLE
        db.execute("UPDATE users SET cash = :plus WHERE id = :user", user = user , plus = (userCash + (stock['price'] * int(shares))));

        # DELETE ROW WHERE SHARE IS 0
        db.execute("DELETE FROM portfolio WHERE share = :share", share = 0);

        flash("Sold!")
        return redirect("/")
    else:
        return render_template("sell.html", stocks=stocks)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)


