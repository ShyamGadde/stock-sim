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
@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")
