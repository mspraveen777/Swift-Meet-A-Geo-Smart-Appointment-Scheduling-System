# SwiftMeet - Geo-Smart Appointment Scheduling System

[![Live Demo](https://img.shields.io/badge/Demo-Live%20on%20Render-6366f1?style=for-the-badge)](https://swift-meet-a-geo-smart-appointment-scheduling-system.onrender.com)

**Live Link**: [https://swift-meet-a-geo-smart-appointment-scheduling-system.onrender.com](https://swift-meet-a-geo-smart-appointment-scheduling-system.onrender.com)
*(Note: If Render assigned you a different URL, you can replace this link in the file).*

SwiftMeet is a premium, state-of-the-art appointment scheduling platform designed with a modern glassmorphic visual system. It enables seamless slot booking, automated rescheduled recommendations for missed appointments, dark mode controls, and a real-time notification engine.

---

## 🌟 Features

### 1. Modern Glassmorphic UI
- Cohesive interactive design system with vibrant gradients, HSL custom color styling, subtle micro-animations, and 3D hover effects.
- Clean responsive layout for both Desktop and Mobile devices.

### 2. Smart Booking & Automated Rescheduling
- **1-Minute Check-In Grace Period**: Clients have up to 1 minute past their appointment time to check-in.
- **Smart Detection**: If a client misses their slot, the app automatically detects it on the main dashboard view.
- **Instant Reschedule Pop-Up**: Prompts the user with the next nearest available slot and offers one-click rescheduling.

### 3. In-App Notification Center
- Interactive bell dropdown popover.
- Displays dynamic notifications for bookings, check-ins, reschedules, cancellations, and missed slots.
- Read/Unread state tracking with indicator dots and real-time badge count synced to `localStorage`.
- "Mark all read" utility.

### 4. Appearance Settings Toggle
- Dual-theme support: **Day Mode** (Light) and **Dark Mode**.
- Accessible from both the User and Admin menus.
- Saved user preference in `localStorage` to prevent style flashing on page load.

### 5. Multi-Channel Notifications
- Prioritized routing: attempts sending **SMS** alerts first.
- Exception-safe fallback to **Email** (SMTP / Brevo) if SMS is unconfigured or fails.
- Local outbox logging (`sms_outbox.log` and `email_outbox.log`) if credentials are not set.

### 6. Admin Panel
- Dashboard overview of analytics and recent activities.
- Create and manage services (services can have distinct names and addresses).
- Create, schedule, and delete individual time slots.
- View all active bookings and mark attendees as checked-in ("Arrived").

---

## 🛠️ Tech Stack
- **Backend**: Python, Flask, Flask-SQLAlchemy (ORM)
- **Database**: SQLite (Local development) / PostgreSQL (Production)
- **Frontend**: HTML5, Vanilla JavaScript, Tailwind CSS (CDN), FontAwesome Icons, Google Fonts, custom CSS variable tokens

---

## 🚀 Local Development Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/mspraveen777/Swift-Meet-A-Geo-Smart-Appointment-Scheduling-System.git
   cd Swift-Meet-A-Geo-Smart-Appointment-Scheduling-System
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Flask application**:
   ```bash
   python app.py
   ```
   Open your browser and navigate to `http://127.0.0.1:5000`.

---

## 🔑 Environment Variables
Configure these variables in your local environment or host provider settings:

| Variable | Description | Example |
| :--- | :--- | :--- |
| `SECRET_KEY` | Flask session cookie key | `my-secret-key` |
| `DATABASE_URL` | PostgreSQL connection string (Production) | `postgresql://...` |
| `SMTP_SERVER` | SMTP email relay server | `smtp-relay.brevo.com` |
| `SMTP_PORT` | SMTP port | `587` |
| `SMTP_USER` | SMTP username | `your-email@example.com` |
| `SMTP_PASSWORD`| SMTP account password/key | `xsmtpsib-...` |
| `SMTP_FROM_EMAIL`| Sender email address | `mspraveen2003@gmail.com` |
| `TWILIO_ACCOUNT_SID`| Twilio Account SID | `AC...` |
| `TWILIO_AUTH_TOKEN`| Twilio API Auth Token | `auth_token_here` |
| `TWILIO_FROM_NUMBER`| Twilio active phone number | `+1234567890` |

---

## 🌐 Production Deployment (Render + Neon Postgres)

1. Get a free PostgreSQL database on [Neon.tech](https://neon.tech/) and copy the connection string.
2. Sign up on [Render.com](https://render.com/) and create a new **Web Service** linked to this GitHub repository.
3. Configure the service parameters:
   - **Runtime**: `Python`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
4. Under **Advanced**, add the `DATABASE_URL` environment variable containing your Neon connection string, and `SECRET_KEY` with a random string.
5. Deploy! Render will build the project and initialize all tables automatically.
