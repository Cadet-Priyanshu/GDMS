
import ssl
import re
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
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.config.from_object(Config)
csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to continue."



def natural_guard_sort_key(guard):
    """
    Sort guard IDs naturally: G2 comes before G10.
    Accepts either a guard dictionary or a plain guard ID.
    """
    guard_id = guard.get("guard_id", "") if isinstance(guard, dict) else guard
    parts = re.split(r"(\d+)", str(guard_id))
    return tuple(
        (1, int(part)) if part.isdigit() else (0, part.casefold())
        for part in parts
    )


# Database connection

def get_db_connection():
    ssl_context = ssl.create_default_context(
        cafile=app.config["TIDB_SSL_CA"]
    )

    return pymysql.connect(
        host=app.config["TIDB_HOST"],
        port=app.config["TIDB_PORT"],
        user=app.config["TIDB_USER"],
        password=app.config["TIDB_PASSWORD"],
        database=app.config["TIDB_NAME"],
        ssl=ssl_context,
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=20
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
            guard_list = sorted(guard_list, key=natural_guard_sort_key)
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



# Daily Duty Entry
@app.route("/roster", methods=["GET", "POST"])
@login_required
def roster():

    if request.method == "POST":

        if current_user.role not in ["ADMIN", "SUPERVISOR"]:
            flash("You do not have permission to enter duty records.", "error")
            return redirect(url_for("roster"))

        duty_date = request.form.get("duty_date", "").strip()

        try:
            selected_date = date.fromisoformat(duty_date)
        except ValueError:
            flash("Please select a valid duty date.", "error")
            return redirect(url_for("roster"))

        connection = get_db_connection()

        try:
            with connection.cursor() as cursor:

                # Load the exact active post/shift combinations for this date sheet.
                cursor.execute("""
                    SELECT a.shift_id, a.post_id
                    FROM post_shift_availability a
                    JOIN posts p ON p.post_id = a.post_id
                    WHERE a.is_active = TRUE
                      AND p.is_active = TRUE
                """)
                valid_slots = sorted(
                    (row["shift_id"], row["post_id"])
                    for row in cursor.fetchall()
                )

                if len(valid_slots) != 15:
                    raise ValueError(
                        "The duty configuration should contain exactly 15 active slots. "
                        "Please check Post & Shift availability before saving."
                    )

                # Valid guard IDs, including inactive guards, so past records
                # can still be entered for guards who have since been deactivated.
                cursor.execute("SELECT guard_id FROM guards")
                valid_guards = {
                    str(row["guard_id"]) for row in cursor.fetchall()
                }

                # Guards marked Rest/Leave for this date cannot be assigned
                # as either the planned guard or the actual replacement.
                cursor.execute("""
                    SELECT guard_id, status
                    FROM guard_day_status
                    WHERE duty_date = %s
                """, (selected_date,))
                unavailable_guards = {
                    str(row["guard_id"]): row["status"]
                    for row in cursor.fetchall()
                }

                allowed_statuses = {
                    "PENDING", "PRESENT", "REPLACED",
                    "ABSENT", "REST", "LEAVE", "CANCELLED"
                }

                entries = []
                guard_assignments = {}

                for shift_id, post_id in valid_slots:
                    key = f"{shift_id}_{post_id}"

                    planned_id = (
                        request.form.get(f"planned_{key}") or ""
                    ).strip() or None

                    replacement_id = (
                        request.form.get(f"actual_{key}") or ""
                    ).strip() or None

                    status = (
                        request.form.get(f"status_{key}") or ""
                    ).strip().upper()

                    # A fully blank slot means no record for that slot.
                    if not planned_id and not replacement_id and not status:
                        continue

                    if not status:
                        raise ValueError(
                            f"Select a Duty Result for Shift {shift_id}, Post {post_id}."
                        )

                    if status not in allowed_statuses:
                        raise ValueError(
                            f"Invalid Duty Result for Shift {shift_id}, Post {post_id}."
                        )

                    if planned_id and planned_id not in valid_guards:
                        raise ValueError(
                            f"Originally assigned guard {planned_id} does not exist."
                        )

                    if replacement_id and replacement_id not in valid_guards:
                        raise ValueError(
                            f"Actual guard {replacement_id} does not exist."
                        )

                    if planned_id and planned_id in unavailable_guards:
                        raise ValueError(
                            f"Guard {planned_id} is marked "
                            f"{unavailable_guards[planned_id]} for this date "
                            f"and cannot be assigned."
                        )

                    if status == "PRESENT":
                        if not planned_id:
                            raise ValueError(
                                f"Select the originally assigned guard for "
                                f"Shift {shift_id}, Post {post_id} before marking Present."
                            )
                        actual_id = planned_id

                    elif status == "REPLACED":
                        if not planned_id or not replacement_id:
                            raise ValueError(
                                f"For Shift {shift_id}, Post {post_id}, select both "
                                f"the originally assigned guard and the replacement guard."
                            )

                        if replacement_id == planned_id:
                            raise ValueError(
                                f"The replacement guard must be different from "
                                f"the originally assigned guard at Shift {shift_id}, "
                                f"Post {post_id}."
                            )

                        if replacement_id in unavailable_guards:
                            raise ValueError(
                                f"Replacement guard {replacement_id} is marked "
                                f"{unavailable_guards[replacement_id]} for this date "
                                f"and cannot be assigned."
                            )

                        actual_id = replacement_id

                    else:
                        # PENDING, ABSENT, REST, LEAVE and CANCELLED
                        # do not award duty credit to an actual guard.
                        actual_id = None

                    # A guard may appear only once per shift across BOTH
                    # planned and actual assignments.
                    slot_identity = (shift_id, post_id)
                    for guard_id in {planned_id, actual_id} - {None}:
                        assignment_identity = (shift_id, guard_id)
                        previous_slot = guard_assignments.get(assignment_identity)

                        if previous_slot is not None and previous_slot != slot_identity:
                            raise ValueError(
                                f"Guard {guard_id} is assigned to more than one "
                                f"post in Shift {shift_id}."
                            )

                        guard_assignments[assignment_identity] = slot_identity

                    entries.append((
                        selected_date,
                        shift_id,
                        post_id,
                        planned_id,
                        actual_id,
                        status
                    ))

                # Replace the complete date sheet atomically.
                # Clearing first avoids transient unique-index conflicts when
                # assignments are swapped between posts. A rollback restores
                # the previous date sheet if any insert fails.
                cursor.execute(
                    "DELETE FROM duty_slots WHERE duty_date = %s",
                    (selected_date,)
                )

                for entry in entries:
                    cursor.execute("""
                        INSERT INTO duty_slots
                        (
                            duty_date,
                            shift_id,
                            post_id,
                            planned_guard_id,
                            actual_guard_id,
                            actual_status
                        )
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, entry)

            connection.commit()

            flash(
                f"Saved {len(entries)} of 15 duty slots for {selected_date}.",
                "success"
            )

        except ValueError as error:
            connection.rollback()
            flash(str(error), "error")

        except pymysql.err.IntegrityError:
            connection.rollback()
            flash(
                "A guard has been assigned more than once in the same shift. "
                "No changes were saved. Please review all 15 slots.",
                "error"
            )

        except Exception:
            connection.rollback()
            app.logger.exception("Error saving daily duty records.")
            flash(
                "An unexpected error occurred. No changes were saved.",
                "error"
            )

        finally:
            connection.close()

        return redirect(url_for("roster", date=duty_date))

    # GET: load the selected date's complete 15-slot duty sheet.
    selected_date = request.args.get("date", date.today().isoformat())

    try:
        date.fromisoformat(selected_date)
    except ValueError:
        selected_date = date.today().isoformat()

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:

            cursor.execute("""
                SELECT
                    s.shift_id,
                    s.shift_name,
                    s.start_time,
                    s.end_time,
                    p.post_id,
                    p.post_code,
                    ds.planned_guard_id,
                    pg.guard_name AS planned_guard_name,
                    ds.actual_guard_id,
                    ag.guard_name AS actual_guard_name,
                    ds.actual_status
                FROM post_shift_availability a
                JOIN posts p ON p.post_id = a.post_id
                JOIN shifts s ON s.shift_id = a.shift_id
                LEFT JOIN duty_slots ds
                    ON ds.duty_date = %s
                    AND ds.shift_id = s.shift_id
                    AND ds.post_id = p.post_id
                LEFT JOIN guards pg
                    ON pg.guard_id = ds.planned_guard_id
                LEFT JOIN guards ag
                    ON ag.guard_id = ds.actual_guard_id
                WHERE a.is_active = TRUE
                  AND p.is_active = TRUE
                ORDER BY s.shift_id, p.post_id
            """, (selected_date,))
            roster_rows = cursor.fetchall()

            cursor.execute("""
                SELECT
                    g.guard_id,
                    g.guard_name,
                    g.is_active,
                    gs.status AS day_status
                FROM guards g
                LEFT JOIN guard_day_status gs
                    ON gs.guard_id = g.guard_id
                    AND gs.duty_date = %s
            """, (selected_date,))
            guards = sorted(
                cursor.fetchall(),
                key=natural_guard_sort_key
            )

    finally:
        connection.close()

    return render_template(
        "roster.html",
        roster_rows=roster_rows,
        guards=guards,
        selected_date=selected_date
    )



# Logout
@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))



# Old attendance URL redirects to the combined duty entry page.
@app.route("/attendance", methods=["GET", "POST"])
@login_required
def attendance():
    return redirect(url_for("roster"))


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
            WHERE g.is_active = TRUE
        """, (selected_date,))

        guards = cursor.fetchall()
        guards = sorted(guards, key=natural_guard_sort_key)

        return render_template(
            "availability.html",
            guards=guards,
            selected_date=selected_date
        )

    finally:
        cursor.close()
        connection.close()

@app.route("/users", methods=["GET", "POST"])
@login_required
def manage_users():

    # Only Admin can access this page
    if current_user.role != "ADMIN":
        flash("You are not authorized to access this page.")
        return redirect(url_for("dashboard"))

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:

            if request.method == "POST":
                username = request.form.get("username", "").strip()
                password = request.form.get("password", "")

                if not username or not password:
                    flash("Username and password are required.")

                elif len(username) > 50:
                    flash("Username cannot exceed 50 characters.")

                elif len(password) < 12:
                    flash("Password must be at least 12 characters.")

                else:
                    cursor.execute(
                        "SELECT user_id FROM users WHERE username = %s",
                        (username,)
                    )

                    if cursor.fetchone():
                        flash("This username already exists.")

                    else:
                        password_hash = generate_password_hash(password)

                        cursor.execute(
                            """
                            INSERT INTO users
                            (username, password_hash, role, is_active)
                            VALUES (%s, %s, 'SUPERVISOR', 1)
                            """,
                            (username, password_hash)
                        )

                        connection.commit()
                        flash("Supervisor account created successfully!")

                return redirect(url_for("manage_users"))

            cursor.execute(
                """
                SELECT user_id, username, role, is_active, created_at
                FROM users
                ORDER BY user_id
                """
            )

            users = cursor.fetchall()

            return render_template("users.html", users=users)

    finally:
        connection.close()

# Duty Analytics
@app.route("/analytics", methods=["GET"])
@login_required
def analytics():

    today = date.today()
    default_start = today.replace(day=1)

    start_date = request.args.get(
        "start_date", default_start.isoformat()
    )
    end_date = request.args.get(
        "end_date", today.isoformat()
    )

    # Validate selected dates
    try:
        start = date.fromisoformat(start_date)
        end = date.fromisoformat(end_date)

        if start > end:
            raise ValueError

    except ValueError:
        flash("Invalid date range selected.", "error")
        start = default_start
        end = today
        start_date = start.isoformat()
        end_date = end.isoformat()

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    g.guard_id,
                    g.guard_name,

                    SUM(
                        CASE
                            WHEN s.shift_name IN ('Shift 1', 'Shift 2')
                            THEN 1 ELSE 0
                        END
                    ) AS day_duties,

                    SUM(
                        CASE
                            WHEN s.shift_name = 'Shift 3'
                            THEN 1 ELSE 0
                        END
                    ) AS night_duties,

                    COUNT(ds.slot_id) AS total_duties

                FROM guards g

                LEFT JOIN duty_slots ds
                    ON ds.actual_guard_id = g.guard_id
                    AND ds.duty_date BETWEEN %s AND %s
                    AND ds.actual_status IN ('PRESENT', 'REPLACED')

                LEFT JOIN shifts s
                    ON s.shift_id = ds.shift_id

                GROUP BY g.guard_id, g.guard_name

                ORDER BY total_duties DESC, g.guard_name
            """, (start_date, end_date))

            guard_stats = cursor.fetchall()

    finally:
        connection.close()

    total_day = sum(
        int(row["day_duties"] or 0) for row in guard_stats
    )

    total_night = sum(
        int(row["night_duties"] or 0) for row in guard_stats
    )

    total_duties = sum(
        int(row["total_duties"] or 0) for row in guard_stats
    )

    return render_template(
        "analytics.html",
        guard_stats=guard_stats,
        start_date=start_date,
        end_date=end_date,
        total_day=total_day,
        total_night=total_night,
        total_duties=total_duties
    )

if __name__ == "__main__":
    app.run(debug=False)
