
from flask import Flask, render_template, redirect, url_for, flash, request
import pymysql
from datetime import date

from flask_wtf.csrf import CSRFProtect

from config import Config
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from werkzeug.security import check_password_hash


app = Flask(__name__)
app.config.from_object(Config)
csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to continue."

# Database connection
def get_db_connection():
    return pymysql.connect(
        host=app.config["DB_HOST"],
        user=app.config["DB_USER"],
        password=app.config["DB_PASSWORD"],
        database=app.config["DB_NAME"],
        cursorclass=pymysql.cursors.DictCursor
    )


# Login form with CSRF protection
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


# Logged-in user
class User(UserMixin):
    def __init__(self, user_id, username, role, is_active):
        self.id = str(user_id)
        self.username = username
        self.role = role
        self._active = bool(is_active)

    @property
    def is_active(self):
        return self._active


@login_manager.user_loader
def load_user(user_id):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM users WHERE user_id = %s",
                (user_id,)
            )
            user = cursor.fetchone()

        if user:
            return User(
                user["user_id"],
                user["username"],
                user["role"],
                user["is_active"]
            )
        return None
    finally:
        connection.close()


# Home page
@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = LoginForm()

    if form.validate_on_submit():
        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT * FROM users
                    WHERE username = %s AND is_active = TRUE
                    """,
                    (form.username.data.strip(),)
                )
                user_data = cursor.fetchone()
        finally:
            connection.close()

        if user_data and check_password_hash(
            user_data["password_hash"], form.password.data
        ):
            user = User(
                user_data["user_id"],
                user_data["username"],
                user_data["role"],
                user_data["is_active"]
            )
            login_user(user)
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "error")

    return render_template("login.html", form=form)


# Dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


# Guard Management
@app.route("/guards", methods=["GET", "POST"])
@login_required
def guards():

    # Only Admin and Supervisor can add guards
    if request.method == "POST":
        if current_user.role not in ["ADMIN", "SUPERVISOR"]:
            flash("You do not have permission to add guards.", "error")
            return redirect(url_for("guards"))

        guard_id = request.form.get("guard_id", "").strip()
        guard_name = request.form.get("guard_name", "").strip()

        if not guard_id or not guard_name:
            flash("Guard ID and Guard Name are required.", "error")
            return redirect(url_for("guards"))

        connection = get_db_connection()

        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO guards (guard_id, guard_name)
                    VALUES (%s, %s)
                    """,
                    (guard_id, guard_name)
                )

            connection.commit()
            flash("Guard added successfully!", "success")

        except pymysql.err.IntegrityError:
            flash("This Guard ID already exists.", "error")

        finally:
            connection.close()

        return redirect(url_for("guards"))

    # Display all guards
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT guard_id, guard_name, is_active
                FROM guards
                ORDER BY guard_id
                """
            )
            guard_list = cursor.fetchall()
    finally:
        connection.close()

    return render_template("guards.html", guards=guard_list)

# Edit guard name
@app.route("/guards/<guard_id>/edit", methods=["POST"])
@login_required
def edit_guard(guard_id):

    if current_user.role not in ["ADMIN", "SUPERVISOR"]:
        flash("You do not have permission to edit guards.", "error")
        return redirect(url_for("guards"))

    guard_name = request.form.get("guard_name", "").strip()

    if not guard_name:
        flash("Guard name cannot be empty.", "error")
        return redirect(url_for("guards"))

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE guards SET guard_name = %s WHERE guard_id = %s",
                (guard_name, guard_id)
            )

            if cursor.rowcount == 0:
                flash("Guard not found or no changes were made.", "error")
            else:
                flash("Guard name updated successfully!", "success")

        connection.commit()

    finally:
        connection.close()

    return redirect(url_for("guards"))


# Activate or deactivate a guard
@app.route("/guards/<guard_id>/toggle", methods=["POST"])
@login_required
def toggle_guard(guard_id):

    if current_user.role not in ["ADMIN", "SUPERVISOR"]:
        flash("You do not have permission to change guard status.", "error")
        return redirect(url_for("guards"))

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE guards
                SET is_active = CASE
                    WHEN is_active = TRUE THEN FALSE
                    ELSE TRUE
                END
                WHERE guard_id = %s
                """,
                (guard_id,)
            )

            if cursor.rowcount == 0:
                flash("Guard not found.", "error")
            else:
                flash("Guard status updated successfully!", "success")

        connection.commit()

    finally:
        connection.close()

    return redirect(url_for("guards"))


# Daily Duty Roster
@app.route("/roster", methods=["GET", "POST"])
@login_required
def roster():

    if request.method == "POST":

        if current_user.role not in ["ADMIN", "SUPERVISOR"]:
            flash("You do not have permission to edit the roster.", "error")
            return redirect(url_for("roster"))

        duty_date = request.form.get("duty_date", "").strip()
        guard_id = request.form.get("guard_id", "").strip() or None

        try:
            selected_date = date.fromisoformat(duty_date)
        except ValueError:
            flash("Please select a valid date.", "error")
            return redirect(url_for("roster"))

        try:
            shift_id = int(request.form.get("shift_id", ""))
            post_id = int(request.form.get("post_id", ""))
        except ValueError:
            flash("Invalid shift or post.", "error")
            return redirect(url_for("roster", date=duty_date))

        connection = get_db_connection()

        try:
            with connection.cursor() as cursor:

                # Confirm that this post operates in this shift
                cursor.execute(
                    """
                    SELECT a.post_id
                    FROM post_shift_availability a
                    JOIN posts p ON p.post_id = a.post_id
                    WHERE a.post_id = %s
                    AND a.shift_id = %s
                    AND a.is_active = TRUE
                    AND p.is_active = TRUE
                    """,
                    (post_id, shift_id)
                )

                if not cursor.fetchone():
                    flash("This post is not available in the selected shift.", "error")
                    return redirect(url_for("roster", date=duty_date))

                # Only active guards can receive new assignments
                if guard_id:
                    cursor.execute(
                        """
                        SELECT guard_id
                        FROM guards
                        WHERE guard_id = %s AND is_active = TRUE
                        """,
                        (guard_id,)
                    )

                    if not cursor.fetchone():
                        flash("Selected guard is not active or does not exist.", "error")
                        return redirect(url_for("roster", date=duty_date))

                    # Prevent assigning guards on Rest or Leave
                    cursor.execute(
                        """
                        SELECT status
                        FROM guard_day_status
                        WHERE guard_id = %s
                        AND duty_date = %s
                        """,
                        (guard_id, selected_date)
                    )

                    day_status = cursor.fetchone()

                    if day_status:
                        flash(
                            f"This guard is marked {day_status['status']} "
                            "on this date and cannot be assigned.",
                            "error"
                        )
                        return redirect(url_for("roster", date=duty_date))

                # Save or update planned assignment
                cursor.execute(
                    """
                    INSERT INTO duty_slots
                        (duty_date, shift_id, post_id, planned_guard_id)
                    VALUES (%s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        planned_guard_id = VALUES(planned_guard_id)
                    """,
                    (selected_date, shift_id, post_id, guard_id)
                )

            connection.commit()
            flash("Roster assignment saved successfully!", "success")

        except pymysql.err.IntegrityError:
            connection.rollback()
            flash(
                "This guard is already assigned to another post in this shift.",
                "error"
            )

        finally:
            connection.close()

        return redirect(url_for("roster", date=duty_date))

    # Display roster for selected date
    selected_date = request.args.get("date", date.today().isoformat())

    try:
        date.fromisoformat(selected_date)
    except ValueError:
        selected_date = date.today().isoformat()

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:

            # Load roster and Rest/Leave status of assigned guards
            cursor.execute(
                """
                SELECT
                    s.shift_id,
                    s.shift_name,
                    s.start_time,
                    s.end_time,
                    p.post_id,
                    p.post_code,
                    ds.planned_guard_id,
                    g.guard_name AS planned_guard_name,
                    g.is_active AS planned_guard_is_active,
                    gs.status AS planned_guard_day_status
                FROM post_shift_availability a
                JOIN posts p ON p.post_id = a.post_id
                JOIN shifts s ON s.shift_id = a.shift_id
                LEFT JOIN duty_slots ds
                    ON ds.duty_date = %s
                    AND ds.shift_id = s.shift_id
                    AND ds.post_id = p.post_id
                LEFT JOIN guards g
                    ON g.guard_id = ds.planned_guard_id
                LEFT JOIN guard_day_status gs
                    ON gs.guard_id = ds.planned_guard_id
                    AND gs.duty_date = %s
                WHERE a.is_active = TRUE
                AND p.is_active = TRUE
                ORDER BY s.shift_id, p.post_id
                """,
                (selected_date, selected_date)
            )

            roster_rows = cursor.fetchall()

            # Load only active guards who are not on Rest or Leave
            cursor.execute(
                """
                SELECT g.guard_id, g.guard_name
                FROM guards g
                WHERE g.is_active = TRUE
                AND NOT EXISTS (
                    SELECT 1
                    FROM guard_day_status gs
                    WHERE gs.guard_id = g.guard_id
                    AND gs.duty_date = %s
                )
                ORDER BY g.guard_name
                """,
                (selected_date,)
            )

            active_guards = cursor.fetchall()

    finally:
        connection.close()

    return render_template(
        "roster.html",
        roster_rows=roster_rows,
        active_guards=active_guards,
        selected_date=selected_date
    )


# Logout
@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/attendance", methods=["GET", "POST"])
@login_required
def attendance():

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        selected_date = request.values.get("duty_date") or date.today().isoformat()

        # Only Admin and Supervisor can update attendance
        if request.method == "POST":

            if current_user.role not in ["ADMIN", "SUPERVISOR"]:
                flash("You do not have permission to update attendance.")
                return redirect(url_for("attendance", duty_date=selected_date))

            slot_id = request.form.get("slot_id")
            status = request.form.get("actual_status")
            actual_guard_id = request.form.get("actual_guard_id") or None

            allowed_statuses = [
                "PENDING", "PRESENT", "ABSENT",
                "REST", "LEAVE", "CANCELLED", "REPLACED"
            ]

            if status not in allowed_statuses:
                flash("Invalid attendance status.")
                return redirect(url_for("attendance", duty_date=selected_date))

            # Find the duty slot and its planned guard
            cursor.execute("""
                SELECT slot_id, duty_date, shift_id, planned_guard_id
                FROM duty_slots
                WHERE slot_id = %s AND duty_date = %s
            """, (slot_id, selected_date))

            slot = cursor.fetchone()

            if not slot:
                flash("Duty slot not found.")
                return redirect(url_for("attendance", duty_date=selected_date))

            planned_guard_id = slot["planned_guard_id"]

            # Present means the planned guard attended
            if status == "PRESENT":
                if not planned_guard_id:
                    flash("Assign a planned guard before marking Present.")
                    return redirect(url_for("attendance", duty_date=selected_date))

                actual_guard_id = planned_guard_id

            # Replaced requires a different substitute guard
            elif status == "REPLACED":
                if not planned_guard_id or not actual_guard_id:
                    flash("Select a replacement guard and ensure a planned guard is assigned.")
                    return redirect(url_for("attendance", duty_date=selected_date))

                if actual_guard_id == planned_guard_id:
                    flash("Replacement guard must be different from the planned guard.")
                    return redirect(url_for("attendance", duty_date=selected_date))

                cursor.execute(
                    "SELECT guard_id FROM guards WHERE guard_id = %s",
                    (actual_guard_id,)
                )

                if not cursor.fetchone():
                    flash("Selected replacement guard does not exist.")
                    return redirect(url_for("attendance", duty_date=selected_date))

            # These statuses do not have an actual guard
            else:
                actual_guard_id = None

            try:
                cursor.execute("""
                    UPDATE duty_slots
                    SET actual_status = %s,
                        actual_guard_id = %s
                    WHERE slot_id = %s
                """, (status, actual_guard_id, slot_id))

                connection.commit()
                flash("Attendance saved successfully.")

            except pymysql.err.IntegrityError:
                connection.rollback()
                flash("This guard is already assigned to another post in the same shift.")

            return redirect(url_for("attendance", duty_date=selected_date))

        # Load attendance records for the selected date
        cursor.execute("""
            SELECT
                ds.slot_id,
                ds.duty_date,
                ds.actual_status,
                ds.actual_guard_id,
                s.shift_name,
                p.post_code,
                ds.planned_guard_id,
                pg.guard_name AS planned_guard_name
            FROM duty_slots ds
            JOIN shifts s ON ds.shift_id = s.shift_id
            JOIN posts p ON ds.post_id = p.post_id
            LEFT JOIN guards pg ON ds.planned_guard_id = pg.guard_id
            WHERE ds.duty_date = %s
            ORDER BY s.shift_id, p.post_code
        """, (selected_date,))

        slots = cursor.fetchall()

        # Load all guards, including inactive guards for historical records
        cursor.execute("""
            SELECT guard_id, guard_name, is_active
            FROM guards
            ORDER BY guard_name
        """)

        guards = cursor.fetchall()

        return render_template(
            "attendance.html",
            slots=slots,
            guards=guards,
            selected_date=selected_date
        )

    finally:
        cursor.close()
        connection.close()

@app.route("/availability", methods=["GET", "POST"])
@login_required
def availability():

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        selected_date = request.values.get("duty_date") or date.today().isoformat()

        # Validate the selected date
        try:
            date.fromisoformat(selected_date)
        except ValueError:
            flash("Invalid date selected.")
            return redirect(url_for("availability"))

        # Save or clear Rest/Leave status
        if request.method == "POST":

            if current_user.role not in ["ADMIN", "SUPERVISOR"]:
                flash("You do not have permission to update availability.")
                return redirect(url_for("availability", duty_date=selected_date))

            guard_id = request.form.get("guard_id")
            status = request.form.get("status")

            if status not in ["", "REST", "LEAVE"]:
                flash("Invalid availability status.")
                return redirect(url_for("availability", duty_date=selected_date))

            # Check that the guard exists
            cursor.execute(
                "SELECT guard_id FROM guards WHERE guard_id = %s",
                (guard_id,)
            )

            if not cursor.fetchone():
                flash("Guard not found.")
                return redirect(url_for("availability", duty_date=selected_date))

            if status == "":
                # Clear existing Rest/Leave status
                cursor.execute("""
                    DELETE FROM guard_day_status
                    WHERE guard_id = %s AND duty_date = %s
                """, (guard_id, selected_date))

                flash("Availability status cleared.")

            else:
                # Add or update Rest/Leave status
                cursor.execute("""
                    INSERT INTO guard_day_status
                    (guard_id, duty_date, status)
                    VALUES (%s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                    status = VALUES(status)
                """, (guard_id, selected_date, status))

                flash("Rest/Leave status saved successfully.")

            connection.commit()

            return redirect(url_for("availability", duty_date=selected_date))

        # Load all guards and their status for the selected date
        cursor.execute("""
            SELECT
                g.guard_id,
                g.guard_name,
                g.is_active,
                gs.status AS day_status
            FROM guards g
            LEFT JOIN guard_day_status gs
                ON g.guard_id = gs.guard_id
                AND gs.duty_date = %s
            ORDER BY g.guard_name
        """, (selected_date,))

        guards = cursor.fetchall()

        return render_template(
            "availability.html",
            guards=guards,
            selected_date=selected_date
        )

    finally:
        cursor.close()
        connection.close()

if __name__ == "__main__":
    app.run(debug=True)
