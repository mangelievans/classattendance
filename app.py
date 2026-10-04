import hmac
import os
import secrets
import sqlite3
from pathlib import Path

from flask import Flask, abort, redirect, render_template, request, session, url_for


app = Flask(__name__, template_folder=".")
app.config.update(
		SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
		SESSION_COOKIE_HTTPONLY=True,
		SESSION_COOKIE_SAMESITE="Lax",
		SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "").lower()
		== "true",
)
DATABASE = Path(
		os.environ.get(
				"DATABASE_PATH", str(Path(__file__).with_name("attendance.db"))
		)
)


def initialize_database():
		DATABASE.parent.mkdir(parents=True, exist_ok=True)
		with sqlite3.connect(DATABASE) as connection:
				connection.execute(
						"""
						CREATE TABLE IF NOT EXISTS attendance (
								id INTEGER PRIMARY KEY AUTOINCREMENT,
								name TEXT NOT NULL,
								registration_number TEXT NOT NULL,
								submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
						)
						"""
				)


initialize_database()


@app.get("/")
def attendance_form():
		return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
		if request.method == "POST":
				expected_password = os.environ.get("ATTENDANCE_PASSWORD")
				if not expected_password:
						abort(503, description="Attendance login is not configured.")

				provided_password = request.form.get("password", "")
				if hmac.compare_digest(provided_password, expected_password):
						session.clear()
						session["attendance_authenticated"] = True
						session["csrf_token"] = secrets.token_urlsafe(32)
						return redirect(url_for("attendance_records"))

				return render_template("login.html", error=True), 401

		return render_template("login.html")


@app.get("/logout")
def logout():
		session.clear()
		return redirect(url_for("login"))


@app.post("/submit")
def submit_attendance():
		name = request.form.get("name", "").strip()
		registration_number = request.form.get("RegNo", "").strip()
		if not name or not registration_number:
				abort(400, description="Name and registration number are required.")

		with sqlite3.connect(DATABASE) as connection:
				connection.execute(
						"INSERT INTO attendance (name, registration_number) VALUES (?, ?)",
						(name, registration_number),
				)
        flash("Submitted successfully")
		return redirect(url_for("attendance_form"))


@app.get("/records")
def attendance_records():
		if not session.get("attendance_authenticated"):
				return redirect(url_for("login"))

		with sqlite3.connect(DATABASE) as connection:
				connection.row_factory = sqlite3.Row
				records = connection.execute(
						"SELECT id, name, registration_number, submitted_at "
						"FROM attendance ORDER BY id DESC"
				).fetchall()

				return render_template(
						"attendancelist.html",
						records=records,
						csrf_token=session["csrf_token"],
				)


@app.post("/records/<int:record_id>/delete")
def delete_attendance(record_id):
		if not session.get("attendance_authenticated"):
				return redirect(url_for("login"))

		expected_token = session.get("csrf_token")
		provided_token = request.form.get("csrf_token", "")
		if not expected_token or not hmac.compare_digest(provided_token, expected_token):
				abort(400, description="Invalid request token.")

		with sqlite3.connect(DATABASE) as connection:
				result = connection.execute(
						"DELETE FROM attendance WHERE id = ?", (record_id,)
				)
				if result.rowcount == 0:
						abort(404)

		return redirect(url_for("attendance_records"))


if __name__ == "__main__":
		app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
