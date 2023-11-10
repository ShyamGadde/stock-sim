from cs50 import SQL
from flask import Flask, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    user_id = session["user_id"]

    shares = db.execute(
        "SELECT symbol, quantity FROM portfolio WHERE user_id = ?",
        user_id,
    )

    cash = db.execute(
        "SELECT cash FROM users WHERE id = ? ",
        user_id,
    )[0]["cash"]
    grand_total = cash

    for share in shares:
        quote = lookup(share["symbol"])

        share["name"] = quote["name"]
        share["price"] = quote["price"]

        total_value = quote["price"] * share["quantity"]
        share["total_value"] = total_value

        grand_total += total_value

    # Display the home page
    return render_template(
        "index.html",
        shares=shares,
        cash=cash,
        grand_total=grand_total,
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    user_id = session["user_id"]

    if request.method == "GET":
        return render_template("buy.html")

    symbol = request.form.get("symbol")

    quote = lookup(symbol)

    if quote is None:
        return apology("invalid symbol", 400)
    else:
        symbol = quote["symbol"]

    quantity = int(request.form.get("shares"))

    cash = db.execute(
        "SELECT cash FROM users WHERE id = ? ",
        user_id,
    )[0]["cash"]

    cost = quantity * quote["price"]
    if cost > cash:
        return apology("can't afford", 400)
    else:
        cash -= cost

    rows = db.execute(
        "SELECT quantity FROM portfolio WHERE user_id = ? AND symbol = ?",
        user_id,
        symbol,
    )

    if len(rows) == 0:
        db.execute(
            "INSERT INTO portfolio (user_id, symbol, quantity) VALUES (?, ?, ?)",
            user_id,
            symbol,
            quantity,
        )
    else:
        updated_quantity = int(rows[0]["quantity"]) + quantity
        db.execute(
            "UPDATE portfolio SET quantity = ? WHERE user_id = ? AND symbol = ?",
            updated_quantity,
            user_id,
            symbol,
        )

    db.execute(
        "INSERT INTO transactions (user_id, symbol, quantity, price) VALUES (?, ?, ?, ?)",
        user_id,
        symbol,
        quantity,
        quote["price"],
    )

    db.execute(
        "UPDATE users SET cash = ? WHERE id = ?",
        cash,
        user_id,
    )

    return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    user_id = session["user_id"]

    transactions = db.execute(
        "SELECT * FROM  transactions WHERE user_id = ? ORDER BY timestamp DESC;",
        user_id,
    )
    return render_template("history.html", transactions=transactions)


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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
    """Get stock quote."""

    if request.method == "GET":
        return render_template("quote.html")

    symbol = request.form.get("symbol")

    quote = lookup(symbol)

    if quote is None:
        return apology("invalid symbol", 400)

    # Redirect user to quote info page
    return render_template("quoted.html", quote=quote)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")

    if password != confirmation:
        return apology("invalid confirmation password", 400)

    rows = db.execute(
        "SELECT * FROM users WHERE username = ?", request.form.get("username")
    )

    if len(rows) != 0:
        return apology("username already exists", 400)

    db.execute(
        "INSERT INTO users (username, hash) VALUES (?, ?)",
        username,
        generate_password_hash(request.form.get("password")),
    )

    return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    user_id = session["user_id"]

    shares = db.execute(
        "SELECT symbol FROM portfolio WHERE user_id = ?",
        user_id,
    )

    if request.method == "GET":
        return render_template("sell.html", shares=shares)

    symbol = request.form.get("symbol")
    quote = lookup(symbol)
    quantity = int(request.form.get("shares"))

    row = db.execute(
        "SELECT quantity FROM portfolio WHERE user_id = ? AND symbol = ?",
        user_id,
        symbol,
    )

    quantity_owned = int(row[0]["quantity"])

    if quantity > quantity_owned:
        return apology("you don't own that many shares", 400)
    else:
        quantity_owned -= quantity

    if quantity_owned == 0:
        db.execute(
            "DELETE FROM portfolio WHERE user_id = ? AND symbol = ?",
            user_id,
            symbol,
        )
    else:
        db.execute(
            "UPDATE portfolio SET quantity = ? WHERE user_id = ? AND symbol = ?",
            quantity_owned,
            user_id,
            symbol,
        )

    db.execute(
        "INSERT INTO transactions (user_id, symbol, quantity, price) VALUES (?, ?, ?, ?)",
        user_id,
        symbol,
        -quantity,
        quote["price"],
    )

    cash = db.execute(
        "SELECT cash FROM users WHERE id = ? ",
        user_id,
    )[0]["cash"]

    received = quantity * quote["price"]
    cash += received
    db.execute(
        "UPDATE users SET cash = ? WHERE id = ?",
        cash,
        user_id,
    )

    return redirect("/")
