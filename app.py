import os
import string
from cs50 import SQL
from flask import Flask, jsonify, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


# @app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():

    ## Get current user id
    user_id = session["user_id"]

    ## SQL enquire information of share
    user_stocks = db.execute("SELECT symbol, SUM(shares) as shares, prices FROM transactions WHERE user_id = ? GROUP BY symbol", user_id)
    cash_db = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    cash = cash_db[0]["cash"]

    holdings = []
    grand_total=0
    for row in user_stocks:
        stock = lookup(row["symbol"])
        holdings.append({
            "symbol": stock["symbol"],
            "name": stock["name"],
            "shares": row["shares"],
            "price": usd(stock["price"]),
            "total": usd(stock["price"] * row["shares"])
        })
        grand_total += stock["price"] * row["shares"]

    grand_total += cash
    return render_template("index.html", holdings=holdings, cash=usd(cash), grand_total=usd(grand_total))





@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "GET":
        return render_template("buy.html")

    else:
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        symbol = symbol.upper()

        if not symbol:
            return apology("Must Give Symbol")

        stock = lookup(symbol.upper())

        if stock == None:
            return apology("Company isn't traded")

        if shares < 0:
            return apology("Invalid amount")

        transaction_value = stock["price"] * shares

        user_id = session["user_id"]

        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        real_cash = user_cash[0]["cash"]

        if real_cash < transaction_value:
            return apology("Insufficient funds")

        updt_cash = real_cash - transaction_value

        db.execute("UPDATE users SET cash = ? WHERE id = ?", updt_cash, user_id)

        date = datetime.datetime.now()

        db.execute("INSERT INTO transactions (user_id, symbol, shares, prices, date) VALUES (?, ?, ?, ?, ?)", user_id, symbol, shares, stock["price"], date)

        flash("Congratulations!")

        return redirect("/")



@app.route("/history")
@login_required
def history():

        ## Get current user id
    user_id = session["user_id"]

    ## SQL enquire information for shares
    user_transactions = db.execute("SELECT * FROM transactions WHERE user_id = ?", user_id)


    return render_template("history.html" , transactions=user_transactions)



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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

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
    if request.method == "GET":
        return render_template("quote.html")

    else:
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("Must Give Symbol")

        stock = lookup(symbol.upper())

        if stock == None:
            return apology("Company isn't traded")

        return render_template("quotes.html", name=stock["name"], price=stock["price"], symbol=stock["symbol"])


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    else:
        #variables for users input
        username = request.form.get("username")
        password = request.form.get("password")

        confirmation = request.form.get("confirmation")

        #Ensures user adds information
        if not username:
            return apology("Must give Username!")

        if not password:
            return apology("Must give Password!")

        if not confirmation:
            return apology("Must confirm Password!")

        #validate password

        if len(password) < 8:
            return apology("Must contain atlease 8 Characters!")

        lowercase = False
        uppercase = False
        num = False
        special = False

        for char in password:
            if(char.isdigit()):
                num = True
            if(char.islower()):
                lowercase = True
            if(char.isupper()):
                uppercase = True
            if(not char.isalnum()):
                special = True

        if lowercase == False:
            return apology("Must contain atleast 1 lowercase letter!")
        if uppercase == False:
            return apology("Must contain atleast 1 uppercase letter!")
        if special == False:
            return apology("Must contain atleast 1 special character!")
        if num == False:
            return apology("Must contain atleast 1 number!")


        #Ensure the passwords match
        if password != confirmation:
            return apology("Passwords must match")

        #variable for password
        hash = generate_password_hash(password)

        try:
            new_user = db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)
        except:
            return apology("Username already exists!")

        session["user_id"] = new_user

        return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
        if request.method == "GET":
            user_id = session["user_id"]

            symbols_users = db.execute("SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0", user_id)

            return render_template("sell.html", symbol=[row["symbol"] for row in symbols_users])

        else:
            symbol = request.form.get("symbol")
            shares = int(request.form.get("shares"))

            if not symbol:
                return apology("Must Give Symbol")

            stock = lookup(symbol.upper())

            if stock == None:
                return apology("Company isn't traded")

            if shares < 0:
                return apology("Invalid amount")


            transaction_value = stock["price"] * shares

            user_id = session["user_id"]

            user_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
            real_cash = user_cash[0]["cash"]

            updt_cash = real_cash + transaction_value

            user_shares = db.execute("SELECT shares FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol", user_id, symbol)
            real_shares = user_shares[0]["shares"]

            if shares > real_shares:
                return apology("You don't have that many shares!")

            db.execute("UPDATE users SET cash = ? WHERE id = ?", updt_cash, user_id)

            date = datetime.datetime.now()

            db.execute("INSERT INTO transactions (user_id, symbol, shares, prices, date) VALUES (?, ?, ?, ?, ?)", user_id, symbol, (-1)*shares, stock["price"], date)

            flash("Sold!")

            return redirect("/")

