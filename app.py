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

BASE_DIR = Path(__file__).resolve().parent

app = Flask(__name__, static_folder='.', static_url_path='')
app.config.update(
    SECRET_KEY="swiftmeet-dev-secret",  # for sessions; replace in production
    SQLALCHEMY_DATABASE_URI=f"sqlite:///{(BASE_DIR / 'swiftmeet.db').as_posix()}",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

db = SQLAlchemy(app)


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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid email or password"}), 400

    session["user_id"] = user.id
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

    service = Service(
        admin_id=user.id,
        name=name,
        type=service_type,
        specialty=(data.get("specialty") or "").strip() or None,
        description=(data.get("description") or "").strip() or None,
        address=address,
        lat=data.get("lat"),
        lng=data.get("lng"),
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
        slot_time = datetime.fromisoformat(time_str)
    except ValueError:
        return jsonify({"error": "Invalid time format"}), 400

    if slot_time <= datetime.utcnow():
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

    now = datetime.utcnow()

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

    now = datetime.utcnow()

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
    slot.booked_at = datetime.utcnow()
    slot.status = "booked"
    db.session.add(slot)
    db.session.commit()

    return jsonify({"slot": slot.to_dict_with_service()})


@app.get("/api/bookings")
@login_required
def api_list_user_bookings():
    """Return all bookings for the current user.

    Includes automatic one-time rescheduling of a missed slot, mirroring the
    JS behaviour (autoRescheduleCandidate) but implemented in Python.
    """

    user = get_current_user()
    now = datetime.utcnow()
    fifteen_minutes = timedelta(minutes=15)

    # First, mark any auto-rescheduled bookings that were missed again as no-show.
    # These should NOT be rescheduled a second time, even if slots are available.
    second_misses = (
        Slot.query.join(Service)
        .filter(
            Slot.booked_by_id == user.id,
            Slot.status == "booked",
            Slot.arrived.is_(False),
            Slot.time + fifteen_minutes < now,
            Slot.auto_rescheduled.is_(True),
        )
        .all()
    )

    for s in second_misses:
        s.status = "no-show"
        db.session.add(s)

    if second_misses:
        db.session.commit()

    # Auto-reschedule one missed, never-auto-rescheduled slot if any.
    missed_candidate = (
        Slot.query.join(Service)
        .filter(
            Slot.booked_by_id == user.id,
            Slot.status == "booked",
            Slot.arrived.is_(False),
            Slot.time + fifteen_minutes < now,
            Slot.auto_rescheduled.is_(False),
        )
        .order_by(Slot.time.asc())
        .first()
    )

    if missed_candidate:
        _find_and_book_next_slot(user, missed_candidate.service_id, missed_candidate, auto=True)

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

    now = datetime.utcnow()
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
