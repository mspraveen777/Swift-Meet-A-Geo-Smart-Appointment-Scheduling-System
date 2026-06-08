from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any

from flask import (
    Flask,
    send_from_directory,
    request,
    jsonify,
    session,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# -----------------------------------------------------------------------------
# Flask + DB setup
# -----------------------------------------------------------------------------

import os

BASE_DIR = Path(__file__).resolve().parent

# Check for database URL in environment (e.g. for Render Postgres integration)
db_url = os.environ.get("DATABASE_URL")
if db_url:
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
else:
    db_url = f"sqlite:///{(BASE_DIR / 'swiftmeet.db').as_posix()}"

app = Flask(__name__, static_folder='.', static_url_path='')
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "swiftmeet-dev-secret"),
    SQLALCHEMY_DATABASE_URI=db_url,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

db = SQLAlchemy(app)


def send_sms(to_number: str, message: str) -> bool:
    """Send SMS using Twilio API if configured, otherwise log to local sms_outbox.log."""
    import os
    import urllib.request
    import urllib.parse
    import base64
    
    # E.164 clean phone number formatting
    clean_number = "".join(c for c in to_number if c.isdigit() or c == "+")
    if clean_number and not clean_number.startswith("+"):
        # Prepend + if not present (default formatting helper)
        clean_number = "+" + clean_number

    print(f"[SMS SENDER] Sending message to {clean_number}: {message}")

    # Log to a local outbox log in the workspace for testing
    log_file = BASE_DIR / "sms_outbox.log"
    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] TO: {clean_number} | MSG: {message}\n")
    except Exception as log_err:
        print(f"[SMS SENDER] Logging failed: {log_err}")

    # Attempt real SMS sending via Twilio
    sid = os.environ.get("TWILIO_ACCOUNT_SID")
    auth_token = os.environ.get("TWILIO_AUTH_TOKEN")
    from_number = os.environ.get("TWILIO_FROM_NUMBER")

    if not (sid and auth_token and from_number):
        print("[SMS SENDER] Twilio environment not fully configured. SMS logged in sms_outbox.log")
        return False

    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    try:
        data = urllib.parse.urlencode({
            "To": clean_number,
            "From": from_number,
            "Body": message
        }).encode("utf-8")

        req = urllib.request.Request(url, data=data, method="POST")
        
        # Twilio requires Basic Authentication
        auth_str = f"{sid}:{auth_token}"
        auth_b64 = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
        req.add_header("Authorization", f"Basic {auth_b64}")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

        with urllib.request.urlopen(req, timeout=5) as response:
            res_body = response.read().decode("utf-8")
            if response.status in (200, 201):
                print("[SMS SENDER] Real Twilio SMS sent successfully.")
                return True
            else:
                print(f"[SMS SENDER] Twilio API error {response.status}: {res_body}")
                return False
    except Exception as e:
        print(f"[SMS SENDER] Failed to connect to Twilio: {e}")
        return False


def send_email(to_email: str, subject: str, message: str) -> bool:
    """Send Email using smtplib if configured, otherwise log to local email_outbox.log."""
    import os
    import smtplib
    from email.mime.text import MIMEText
    from email.header import Header

    # Log clean print details (strip HTML tags if sending HTML to console for neatness)
    clean_msg = message
    if "<html" in message.lower() or "<!doctype" in message.lower():
        import re
        clean_msg = re.sub('<[^<]+?>', '', message)[:100] + "..." # Truncate for console logging

    print(f"[EMAIL SENDER] Sending email to {to_email}: [{subject}] {clean_msg}")

    # Log to a local outbox log in the workspace for testing
    log_file = BASE_DIR / "email_outbox.log"
    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] TO: {to_email} | SUBJECT: {subject} | MSG: {message}\n")
    except Exception as log_err:
        print(f"[EMAIL SENDER] Logging failed: {log_err}")

    # Attempt real Email sending via SMTP
    smtp_server = os.environ.get("SMTP_SERVER")
    smtp_port = os.environ.get("SMTP_PORT")
    smtp_user = os.environ.get("SMTP_USER")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    from_email = os.environ.get("SMTP_FROM_EMAIL") or smtp_user

    if not (smtp_server and smtp_port and smtp_user and smtp_password):
        print("[EMAIL SENDER] SMTP credentials not fully configured. Email logged in email_outbox.log")
        return False

    try:
        port = int(smtp_port)
        # Setup message format (HTML or Plain)
        subtype = "html" if ("<html" in message.lower() or "<!doctype" in message.lower()) else "plain"
        msg = MIMEText(message, subtype, "utf-8")
        msg["Subject"] = Header(subject, "utf-8")
        msg["From"] = from_email
        msg["To"] = to_email

        if port == 465:
            server = smtplib.SMTP_SSL(smtp_server, port, timeout=10)
        else:
            server = smtplib.SMTP(smtp_server, port, timeout=10)
            server.starttls()

        server.login(smtp_user, smtp_password)
        server.sendmail(from_email, [to_email], msg.as_string())
        server.quit()
        print("[EMAIL SENDER] Real SMTP Email sent successfully.")
        return True
    except Exception as e:
        print(f"[EMAIL SENDER] Failed to send email: {e}")
        return False


def wrap_email_template(subtitle: str, content_html: str) -> str:
    """Wrap content in a premium responsive HTML email template."""
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: #f4f5f7;
      color: #333333;
      margin: 0;
      padding: 0;
    }}
    .wrapper {{
      width: 100%;
      background-color: #f4f5f7;
      padding: 40px 0;
    }}
    .container {{
      max-width: 600px;
      margin: 0 auto;
      background-color: #ffffff;
      border-radius: 16px;
      overflow: hidden;
      box-shadow: 0 4px 12px rgba(0,0,0,0.05);
    }}
    .header {{
      background: linear-gradient(135deg, #6366f1, #4f46e5);
      color: #ffffff;
      padding: 40px 20px;
      text-align: center;
    }}
    .header h1 {{
      margin: 0;
      font-size: 28px;
      font-weight: 700;
      letter-spacing: -0.5px;
    }}
    .header p {{
      margin: 8px 0 0 0;
      opacity: 0.9;
      font-size: 16px;
    }}
    .content {{
      padding: 40px 30px;
    }}
    .card {{
      background-color: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
    }}
    .card-title {{
      font-weight: 600;
      color: #1e293b;
      margin-bottom: 12px;
      font-size: 16px;
    }}
    .details-row {{
      margin-bottom: 8px;
      font-size: 14px;
    }}
    .details-label {{
      color: #64748b;
      font-weight: 500;
      width: 120px;
      display: inline-block;
    }}
    .details-value {{
      color: #0f172a;
      font-weight: 600;
    }}
    .btn {{
      display: inline-block;
      background-color: #4f46e5;
      color: #ffffff !important;
      padding: 12px 24px;
      border-radius: 8px;
      text-decoration: none;
      font-weight: 600;
      font-size: 15px;
      margin-top: 16px;
      text-align: center;
    }}
    .btn:hover {{
      background-color: #4338ca;
    }}
    .footer {{
      text-align: center;
      padding: 24px;
      font-size: 12px;
      color: #94a3b8;
      background-color: #f8fafc;
      border-top: 1px solid #f1f5f9;
    }}
    .footer a {{
      color: #6366f1;
      text-decoration: none;
    }}
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="container">
      <div class="header">
        <h1>SwiftMeet</h1>
        <p>{subtitle}</p>
      </div>
      <div class="content">
        {content_html}
      </div>
      <div class="footer">
        <p>Sent by SwiftMeet Inc. &bull; Secure Appointment Booking</p>
        <p>Need help? <a href="http://127.0.0.1:5000">Visit our website</a></p>
      </div>
    </div>
  </div>
</body>
</html>"""


def notify_user(user: User, subject: str, message: str, email_html_content: str = None) -> None:
    """Send SMS to user's phone if possible, fallback to email if SMS fails/not possible."""
    try:
        sms_sent = False
        if user.phone:
            sms_sent = send_sms(user.phone, message)
        
        if not sms_sent:
            # Fallback to email
            if user.email:
                if email_html_content:
                    send_email(user.email, subject, email_html_content)
                else:
                    send_email(user.email, subject, message)
            else:
                print(f"[NOTIFY] SMS failed and user has no email. Notification dropped.")
    except Exception as e:
        print(f"[NOTIFY] Unexpected error in notify_user: {e}")


# -----------------------------------------------------------------------------
# Models (mirror existing Firestore structure / logic)
# -----------------------------------------------------------------------------

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(50))
    place = db.Column(db.String(100))
    role = db.Column(db.String(20), default="user")  # "user" or "admin"
    created_at = db.Column(db.DateTime, default=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "phone": self.phone,
            "place": self.place,
            "role": self.role,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Service(db.Model):
    __tablename__ = "services"

    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    admin = db.relationship("User", backref="services")

    name = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(120), nullable=False)
    specialty = db.Column(db.String(120))
    description = db.Column(db.Text)
    address = db.Column(db.String(500), nullable=False)
    lat = db.Column(db.Float)  # optional: if you later geocode via Python
    lng = db.Column(db.Float)

    created_at = db.Column(db.DateTime, default=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "admin_id": self.admin_id,
            "name": self.name,
            "type": self.type,
            "specialty": self.specialty,
            "description": self.description,
            "address": self.address,
            "lat": self.lat,
            "lng": self.lng,
            "coords": {"lat": self.lat, "lng": self.lng} if (self.lat is not None and self.lng is not None) else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Slot(db.Model):
    __tablename__ = "slots"

    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey("services.id"), nullable=False)
    service = db.relationship("Service", backref="slots")

    time = db.Column(db.DateTime, nullable=False)
    booked = db.Column(db.Boolean, default=False)
    booked_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    booked_by = db.relationship("User")
    booked_by_name = db.Column(db.String(120))
    booked_at = db.Column(db.DateTime)

    status = db.Column(
        db.String(20),
        default="available",
    )  # available / booked / arrived / no-show / cancelled
    auto_rescheduled = db.Column(db.Boolean, default=False)
    arrived = db.Column(db.Boolean, default=False)

    def to_dict_basic(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "service_id": self.service_id,
            "time": self.time.isoformat(),
            "booked": self.booked,
            "booked_by_id": self.booked_by_id,
            "booked_by_name": self.booked_by_name,
            "booked_at": self.booked_at.isoformat() if self.booked_at else None,
            "status": self.status,
            "autoRescheduled": self.auto_rescheduled,
            "arrived": self.arrived,
        }

    def to_dict_with_service(self) -> Dict[str, Any]:
        return {
            **self.to_dict_basic(),
            "service": self.service.to_dict() if self.service else None,
        }


with app.app_context():
    db.create_all()


# -----------------------------------------------------------------------------
# Auth helpers
# -----------------------------------------------------------------------------

def get_current_user() -> Optional[User]:
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db.session.get(User, user_id)


def login_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Authentication required"}), 401
        return fn(*args, **kwargs)

    return wrapper


def admin_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user or user.role != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return fn(*args, **kwargs)

    return wrapper


# -----------------------------------------------------------------------------
# Static SPA routes
# -----------------------------------------------------------------------------

@app.route("/")
def index() -> Any:
    """Serve the main SwiftMeet single-page app."""
    return send_from_directory(".", "index.html")


@app.route("/<path:path>")
def static_proxy(path: str) -> Any:
    """Serve any other files (JS, images, etc.) from the project directory."""
    return send_from_directory(".", path)


# -----------------------------------------------------------------------------
# Auth API
# -----------------------------------------------------------------------------

@app.post("/api/register")
def api_register():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    phone = (data.get("phone") or "").strip()
    place = (data.get("place") or "").strip()
    role = data.get("role") or "user"

    if not (name and email and password and phone and place):
        return jsonify({"error": "All fields are required."}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered."}), 400

    user = User(
        name=name,
        email=email,
        password_hash=generate_password_hash(password),
        phone=phone,
        place=place,
        role=role if role in {"user", "admin"} else "user",
    )
    db.session.add(user)
    db.session.commit()

    session["user_id"] = user.id
    return jsonify({"user": user.to_dict()})


@app.post("/api/login")
def api_login():
    data = request.get_json(force=True)
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    role = data.get("role") or "user"

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid email or password"}), 400

    if user.role != role:
        if role == "admin":
            return jsonify({"error": "Invalid admin"}), 400
        else:
            return jsonify({"error": "Invalid user credentials"}), 400

    session["user_id"] = user.id
    return jsonify({"user": user.to_dict()})


@app.post("/api/profile")
@login_required
def api_update_profile():
    user = get_current_user()
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    phone = (data.get("phone") or "").strip()
    place = (data.get("place") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    current_password = data.get("current_password") or ""

    if not (name and phone and place):
        return jsonify({"error": "Name, phone and place are required"}), 400

    if (email or password) and not current_password:
        return jsonify({"error": "Current password is required to update email or password"}), 400

    if current_password:
        if not check_password_hash(user.password_hash, current_password):
            return jsonify({"error": "Incorrect current password"}), 400
        
        if email and email != user.email:
            if User.query.filter_by(email=email).first():
                return jsonify({"error": "Email already registered"}), 400
            user.email = email
        
        if password:
            user.password_hash = generate_password_hash(password)

    user.name = name
    user.phone = phone
    user.place = place
    db.session.commit()
    return jsonify({"user": user.to_dict()})


@app.post("/api/logout")
def api_logout():
    session.clear()
    return jsonify({"ok": True})


@app.get("/api/me")
def api_me():
    user = get_current_user()
    if not user:
        return jsonify({"user": None})
    return jsonify({"user": user.to_dict()})


# -----------------------------------------------------------------------------
# Services API (admin)
# -----------------------------------------------------------------------------

@app.get("/api/admin/services")
@admin_required
def api_admin_list_services():
    user = get_current_user()
    services = Service.query.filter_by(admin_id=user.id).order_by(Service.created_at.desc()).all()
    return jsonify({"services": [s.to_dict() for s in services]})


@app.post("/api/admin/services")
@admin_required
def api_admin_create_service():
    user = get_current_user()
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    service_type = (data.get("type") or "").strip()
    address = (data.get("address") or "").strip()

    if not (name and service_type and address):
        return jsonify({"error": "name, type and address are required"}), 400

    coords = data.get("coords") or {}
    lat = data.get("lat") or coords.get("lat")
    lng = data.get("lng") or coords.get("lng")

    service = Service(
        admin_id=user.id,
        name=name,
        type=service_type,
        specialty=(data.get("specialty") or "").strip() or None,
        description=(data.get("description") or "").strip() or None,
        address=address,
        lat=lat,
        lng=lng,
    )
    db.session.add(service)
    db.session.commit()
    return jsonify({"service": service.to_dict()}), 201


@app.delete("/api/admin/services/<int:service_id>")
@admin_required
def api_admin_delete_service(service_id: int):
    user = get_current_user()
    service = Service.query.filter_by(id=service_id, admin_id=user.id).first()
    if not service:
        return jsonify({"error": "Service not found"}), 404

    # Delete associated slots first
    Slot.query.filter_by(service_id=service.id).delete()
    db.session.delete(service)
    db.session.commit()
    return jsonify({"ok": True})


@app.delete("/api/admin/services")
@admin_required
def api_admin_delete_all_services():
    user = get_current_user()
    services = Service.query.filter_by(admin_id=user.id).all()
    for service in services:
        Slot.query.filter_by(service_id=service.id).delete()
        db.session.delete(service)
    db.session.commit()
    return jsonify({"ok": True})


# -----------------------------------------------------------------------------
# Slots API (admin + search for users)
# -----------------------------------------------------------------------------

@app.get("/api/admin/services/<int:service_id>/slots")
@admin_required
def api_admin_list_slots(service_id: int):
    user = get_current_user()
    service = Service.query.filter_by(id=service_id, admin_id=user.id).first()
    if not service:
        return jsonify({"error": "Service not found"}), 404

    slots = Slot.query.filter_by(service_id=service.id).order_by(Slot.time.asc()).all()
    return jsonify({"slots": [s.to_dict_basic() for s in slots]})


@app.post("/api/admin/services/<int:service_id>/slots")
@admin_required
def api_admin_create_slot(service_id: int):
    user = get_current_user()
    service = Service.query.filter_by(id=service_id, admin_id=user.id).first()
    if not service:
        return jsonify({"error": "Service not found"}), 404

    data = request.get_json(force=True)
    time_str = data.get("time")
    if not time_str:
        return jsonify({"error": "time is required (ISO 8601)"}), 400

    try:
        if time_str.endswith('Z'):
            time_str = time_str[:-1] + '+00:00'
        slot_time = datetime.fromisoformat(time_str)
    except ValueError:
        try:
            slot_time = datetime.strptime(time_str.split('.')[0], "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return jsonify({"error": "Invalid time format"}), 400

    if slot_time.tzinfo is not None:
        slot_time = slot_time.astimezone().replace(tzinfo=None)

    if slot_time <= datetime.now():
        return jsonify({"error": "Cannot add a slot in the past"}), 400

    slot = Slot(
        service_id=service.id,
        time=slot_time,
        booked=False,
        status="available",
    )
    db.session.add(slot)
    db.session.commit()
    return jsonify({"slot": slot.to_dict_basic()}), 201


@app.delete("/api/admin/services/<int:service_id>/slots/<int:slot_id>")
@admin_required
def api_admin_delete_slot(service_id: int, slot_id: int):
    user = get_current_user()
    service = Service.query.filter_by(id=service_id, admin_id=user.id).first()
    if not service:
        return jsonify({"error": "Service not found"}), 404

    slot = Slot.query.filter_by(id=slot_id, service_id=service.id).first()
    if not slot:
        return jsonify({"error": "Slot not found"}), 404

    db.session.delete(slot)
    db.session.commit()
    return jsonify({"ok": True})


@app.get("/api/search/slots")
@login_required
def api_search_slots():
    """Search future available slots by service type.

    Mirrors the Firestore query used in the JS: filter by type tokens and only
    return future, unbooked slots, grouped client-side.
    """

    service_type = (request.args.get("service_type") or "").strip().lower()
    if not service_type:
        return jsonify({"error": "service_type is required"}), 400

    now = datetime.now()

    services_q = Service.query
    services_q = services_q.filter(Service.type.ilike(f"%{service_type}%"))
    services = services_q.all()
    if not services:
        return jsonify({"slots": []})

    service_ids = [s.id for s in services]
    slots = (
        Slot.query.filter(
            Slot.service_id.in_(service_ids),
            Slot.booked.is_(False),
            Slot.time > now,
        )
        .order_by(Slot.time.asc())
        .all()
    )

    return jsonify({"slots": [s.to_dict_with_service() for s in slots]})


# -----------------------------------------------------------------------------
# Bookings API (user + admin views) – mirrors existing JS logic
# -----------------------------------------------------------------------------


def _find_and_book_next_slot(user: User, service_id: int, old_slot: Slot, *, auto: bool) -> Optional[Slot]:
    """Find earliest future free slot for the same service and book it.

    Mirrors the JS findAndBookNextSlot logic and the automatic reschedule.
    """

    now = datetime.now()

    next_slot = (
        Slot.query.filter(
            Slot.service_id == service_id,
            Slot.booked.is_(False),
            Slot.time > now,
        )
        .order_by(Slot.time.asc())
        .first()
    )

    # Mark old slot as no-show regardless of whether we find a new one.
    old_slot.status = "no-show"
    db.session.add(old_slot)

    if not next_slot:
        db.session.commit()
        return None

    next_slot.booked = True
    next_slot.booked_by_id = user.id
    next_slot.booked_by_name = user.name
    next_slot.booked_at = now
    next_slot.status = "booked"
    next_slot.auto_rescheduled = auto
    db.session.add(next_slot)
    db.session.commit()
    return next_slot


@app.post("/api/bookings")
@login_required
def api_book_slot():
    data = request.get_json(force=True)
    slot_id = data.get("slot_id")
    if not slot_id:
        return jsonify({"error": "slot_id is required"}), 400

    user = get_current_user()

    slot = db.session.get(Slot, slot_id)
    if not slot or slot.booked:
        return jsonify({"error": "Slot not available"}), 400

    slot.booked = True
    slot.booked_by_id = user.id
    slot.booked_by_name = user.name
    slot.booked_at = datetime.now()
    slot.status = "booked"
    db.session.add(slot)
    db.session.commit()

    # Send notification
    slot_time_str = slot.time.strftime('%Y-%m-%d %I:%M %p')
    subject = "SwiftMeet Appointment Scheduled"
    sms_msg = f"SwiftMeet: Your appointment for {slot.service.name} is successfully scheduled on {slot_time_str}."
    
    email_html = f"""
    <p>Hello <strong>{user.name}</strong>,</p>
    <p>Your appointment has been successfully scheduled. Here are your booking details:</p>
    <div class="card">
      <div class="card-title">Booking Details</div>
      <div class="details-row">
        <span class="details-label">Service:</span>
        <span class="details-value">{slot.service.name}</span>
      </div>
      <div class="details-row">
        <span class="details-label">Date & Time:</span>
        <span class="details-value">{slot_time_str}</span>
      </div>
      <div class="details-row">
        <span class="details-label">Address:</span>
        <span class="details-value">{slot.service.address}</span>
      </div>
    </div>
    <p>Please arrive 5-10 minutes prior to your scheduled time.</p>
    <a href="http://127.0.0.1:5000" class="btn">View on Dashboard</a>
    """
    email_content = wrap_email_template("Appointment Confirmed", email_html)
    notify_user(user, subject, sms_msg, email_content)

    return jsonify({"slot": slot.to_dict_with_service()})


@app.get("/api/bookings")
@login_required
def api_list_user_bookings():
    """Return all bookings for the current user, marking missed slots as no-show."""
    user = get_current_user()
    now = datetime.now()
    fifteen_minutes = timedelta(minutes=15)

    # Detect missed bookings and mark them as no-show in the database
    missed_bookings = (
        Slot.query.filter(
            Slot.booked_by_id == user.id,
            Slot.status == "booked",
            Slot.time < now - timedelta(minutes=1)
        )
        .all()
    )
    if missed_bookings:
        for b in missed_bookings:
            b.status = "no-show"
            
            # Suggest next available slot in email
            next_slot = (
                Slot.query.filter(
                    Slot.service_id == b.service_id,
                    Slot.booked.is_(False),
                    Slot.time > now,
                )
                .order_by(Slot.time.asc())
                .first()
            )
            
            slot_time_str = b.time.strftime('%Y-%m-%d %I:%M %p')
            subject = "SwiftMeet Appointment Missed"
            sms_msg = f"SwiftMeet: You missed your appointment for {b.service.name} at {slot_time_str}. Log in to SwiftMeet to confirm your reschedule."
            
            if next_slot:
                next_slot_time_str = next_slot.time.strftime('%Y-%m-%d %I:%M %p')
                next_slot_html = f"""
                <div class="card" style="border-left: 4px solid #6366f1;">
                  <div class="card-title" style="color: #6366f1;">Suggested Next Available Slot</div>
                  <div class="details-row">
                    <span class="details-label">Service:</span>
                    <span class="details-value">{b.service.name}</span>
                  </div>
                  <div class="details-row">
                    <span class="details-label">Date & Time:</span>
                    <span class="details-value">{next_slot_time_str}</span>
                  </div>
                  <p style="margin: 12px 0 0 0; font-size: 13px; color: #64748b;">You can log in to SwiftMeet and confirm this reschedule in one click.</p>
                </div>
                """
            else:
                next_slot_html = f"""
                <div class="card" style="border-left: 4px solid #ef4444;">
                  <div class="card-title" style="color: #ef4444;">No Slots Currently Available</div>
                  <p style="margin: 0; font-size: 14px; color: #64748b;">There are no immediate open slots for this service. Please log in to the dashboard to check for new openings later.</p>
                </div>
                """
                
            email_html = f"""
            <p>Hello <strong>{user.name}</strong>,</p>
            <p>We missed you! It looks like you were unable to make your scheduled appointment for <strong>{b.service.name}</strong> on <strong>{slot_time_str}</strong>.</p>
            <p>Don't worry, we've kept your spot open for rescheduling.</p>
            {next_slot_html}
            <a href="http://127.0.0.1:5000" class="btn">Reschedule Appointment</a>
            """
            email_content = wrap_email_template("Appointment Missed", email_html)
            notify_user(user, subject, sms_msg, email_content)
        db.session.commit()

    # Now fetch all bookings for the user.
    slots = (
        Slot.query.join(Service)
        .filter(Slot.booked_by_id == user.id)
        .order_by(Slot.time.desc())
        .all()
    )

    return jsonify({"bookings": [s.to_dict_with_service() for s in slots]})


@app.post("/api/bookings/<int:slot_id>/arrived")
@login_required
def api_mark_arrived(slot_id: int):
    user = get_current_user()
    slot = Slot.query.filter_by(id=slot_id, booked_by_id=user.id).first()
    if not slot:
        return jsonify({"error": "Booking not found"}), 404

    slot.status = "arrived"
    slot.arrived = True
    db.session.add(slot)
    db.session.commit()

    return jsonify({"slot": slot.to_dict_with_service()})


@app.get("/api/bookings/<int:slot_id>/next-available")
@login_required
def api_booking_next_available(slot_id: int):
    user = get_current_user()
    old_slot = Slot.query.filter_by(id=slot_id, booked_by_id=user.id).first()
    if not old_slot:
        return jsonify({"error": "Booking not found"}), 404

    now = datetime.now()
    next_slot = (
        Slot.query.filter(
            Slot.service_id == old_slot.service_id,
            Slot.booked.is_(False),
            Slot.time > now,
        )
        .order_by(Slot.time.asc())
        .first()
    )

    if not next_slot:
        return jsonify({"next_slot": None}), 200

    return jsonify({"next_slot": next_slot.to_dict_with_service()})


@app.post("/api/bookings/<int:slot_id>/reschedule-confirm")
@login_required
def api_booking_reschedule_confirm(slot_id: int):
    user = get_current_user()
    old_slot = Slot.query.filter_by(id=slot_id, booked_by_id=user.id).first()
    if not old_slot:
        return jsonify({"error": "Booking not found"}), 404

    data = request.get_json(force=True)
    next_slot_id = data.get("next_slot_id")
    if not next_slot_id:
        return jsonify({"error": "next_slot_id is required"}), 400

    next_slot = Slot.query.filter_by(id=next_slot_id, service_id=old_slot.service_id, booked=False).first()
    if not next_slot:
        return jsonify({"error": "Target slot is no longer available"}), 400

    # Mark old slot as no-show
    old_slot.status = "no-show"
    old_slot.auto_rescheduled = True
    db.session.add(old_slot)

    # Book new slot
    now = datetime.now()
    next_slot.booked = True
    next_slot.booked_by_id = user.id
    next_slot.booked_by_name = user.name
    next_slot.booked_at = now
    next_slot.status = "booked"
    next_slot.auto_rescheduled = True
    db.session.add(next_slot)

    db.session.commit()

    # Send notification
    next_slot_time_str = next_slot.time.strftime('%Y-%m-%d %I:%M %p')
    subject = "SwiftMeet Appointment Rescheduled"
    sms_msg = f"SwiftMeet: Your appointment for {next_slot.service.name} has been rescheduled to {next_slot_time_str}."
    
    email_html = f"""
    <p>Hello <strong>{user.name}</strong>,</p>
    <p>Your appointment has been successfully rescheduled. Here are your new booking details:</p>
    <div class="card">
      <div class="card-title">New Booking Details</div>
      <div class="details-row">
        <span class="details-label">Service:</span>
        <span class="details-value">{next_slot.service.name}</span>
      </div>
      <div class="details-row">
        <span class="details-label">Date & Time:</span>
        <span class="details-value">{next_slot_time_str}</span>
      </div>
      <div class="details-row">
        <span class="details-label">Address:</span>
        <span class="details-value">{next_slot.service.address}</span>
      </div>
    </div>
    <a href="http://127.0.0.1:5000" class="btn">View on Dashboard</a>
    """
    email_content = wrap_email_template("Appointment Rescheduled", email_html)
    notify_user(user, subject, sms_msg, email_content)

    return jsonify({"new_slot": next_slot.to_dict_with_service()})


@app.post("/api/bookings/<int:slot_id>/find-next-slot")
@login_required
def api_find_next_slot(slot_id: int):
    """Manual "Find Next Slot" action (no-show reschedule)."""

    user = get_current_user()
    old_slot = Slot.query.filter_by(id=slot_id, booked_by_id=user.id).first()
    if not old_slot:
        return jsonify({"error": "Booking not found"}), 404

    new_slot = _find_and_book_next_slot(user, old_slot.service_id, old_slot, auto=False)
    if not new_slot:
        return jsonify({"message": "No next available slots"}), 200

    # Send notification
    if new_slot:
        new_slot_time_str = new_slot.time.strftime('%Y-%m-%d %I:%M %p')
        subject = "SwiftMeet Appointment Rescheduled"
        sms_msg = f"SwiftMeet: Your appointment for {new_slot.service.name} has been rescheduled to {new_slot_time_str}."
        
        email_html = f"""
        <p>Hello <strong>{user.name}</strong>,</p>
        <p>Your appointment has been successfully rescheduled. Here are your new booking details:</p>
        <div class="card">
          <div class="card-title">New Booking Details</div>
          <div class="details-row">
            <span class="details-label">Service:</span>
            <span class="details-value">{new_slot.service.name}</span>
          </div>
          <div class="details-row">
            <span class="details-label">Date & Time:</span>
            <span class="details-value">{new_slot_time_str}</span>
          </div>
          <div class="details-row">
            <span class="details-label">Address:</span>
            <span class="details-value">{new_slot.service.address}</span>
          </div>
        </div>
        <a href="http://127.0.0.1:5000" class="btn">View on Dashboard</a>
        """
        email_content = wrap_email_template("Appointment Rescheduled", email_html)
        notify_user(user, subject, sms_msg, email_content)

    return jsonify({"new_slot": new_slot.to_dict_with_service()})


# Admin bookings view (all bookings for admin's services)
@app.get("/api/admin/bookings")
@admin_required
def api_admin_bookings():
    user = get_current_user()

    services = Service.query.filter_by(admin_id=user.id).all()
    if not services:
        return jsonify({"bookings": []})

    service_ids = [s.id for s in services]

    # First detect missed bookings for these services and mark them as no-show
    now = datetime.now()
    missed_bookings = (
        Slot.query.filter(
            Slot.service_id.in_(service_ids),
            Slot.status == "booked",
            Slot.time < now - timedelta(minutes=1)
        )
        .all()
    )
    if missed_bookings:
        for b in missed_bookings:
            b.status = "no-show"
        db.session.commit()

    slots = (
        Slot.query.join(Service)
        .filter(Slot.service_id.in_(service_ids), Slot.booked.is_(True))
        .order_by(Slot.time.asc())
        .all()
    )

    return jsonify({"bookings": [s.to_dict_with_service() for s in slots]})


@app.post("/api/admin/bookings/<int:slot_id>/arrived")
@admin_required
def api_admin_mark_arrived(slot_id: int):
    slot = db.session.get(Slot, slot_id)
    if not slot or not slot.booked:
        return jsonify({"error": "Booking not found"}), 404

    slot.status = "arrived"
    slot.arrived = True
    db.session.add(slot)
    db.session.commit()

    return jsonify({"slot": slot.to_dict_with_service()})


# -----------------------------------------------------------------------------
# Admin dashboard metrics (optional, mirrors JS stats)
# -----------------------------------------------------------------------------

@app.get("/api/admin/dashboard-metrics")
@admin_required
def api_admin_dashboard_metrics():
    user = get_current_user()
    services = Service.query.filter_by(admin_id=user.id).all()
    total_services = len(services)
    service_ids = [s.id for s in services]

    now = datetime.now()
    today_start = datetime(now.year, now.month, now.day)

    available_slots = 0
    booked_today = 0
    pending_actions = 0

    if service_ids:
        slots = Slot.query.filter(Slot.service_id.in_(service_ids)).all()
        for s in slots:
            if not s.booked:
                available_slots += 1
            else:
                if s.booked_at and s.booked_at >= today_start:
                    booked_today += 1
                if s.status == "booked" and s.time < today_start and not s.arrived:
                    pending_actions += 1

    return jsonify(
        {
            "total_services": total_services,
            "available_slots": available_slots,
            "booked_today": booked_today,
            "pending_actions": pending_actions,
        }
    )


# -----------------------------------------------------------------------------
# Main entry
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    # Run on localhost so browser treats it as a secure origin for geolocation
    app.run(host="127.0.0.1", port=5000, debug=True)
