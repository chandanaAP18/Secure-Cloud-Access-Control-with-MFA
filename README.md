# Secure Cloud Access Control with Multi-Factor Authentication

This project implements the PBL topic from the PDF using Django, HTML/CSS/JavaScript, email OTP verification, and MySQL-ready configuration.

## Features

- User registration with role assignment (`Admin` or `User`)
- Password-based sign in followed by email OTP verification
- Role-based dashboards
- Secure password hashing through Django's auth framework
- Login activity audit trail with IP address and user-agent capture
- MySQL-ready configuration for VS Code/local development
- Unit, integration, and system-style test coverage

## Local setup

1. Create a virtual environment and install dependencies:
   `python -m venv .venv`
   `.\.venv\Scripts\activate`
   `python -m pip install -r requirements.txt`
2. Create a `.env` file from `.env.example` and fill in your email/MySQL values.
3. Run migrations:
   `python manage.py makemigrations`
   `python manage.py migrate`
4. Create an admin user:
   `python manage.py createsuperuser`
5. Start the app:
   `python manage.py runserver`

## Real OTP emails

- The app already sends OTP to the user's email in `accounts/services.py`.
- To receive OTP like normal apps, create a `.env` file and configure SMTP credentials.
- For Gmail, use your Gmail address in `EMAIL_HOST_USER`, set `EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend`, and use a Google App Password in `EMAIL_HOST_PASSWORD`.
- Then restart the server and OTPs will be delivered to mail instead of printing in the terminal.

## MySQL in VS Code

- Install a MySQL server locally or use XAMPP / MySQL Community Server.
- Use the values from `.env.example`.
- Set `USE_MYSQL=True` before running migrations.
- In VS Code, connect using a MySQL extension to `127.0.0.1:3306` with the same credentials.

## Testing

- Django test runner:
  `python manage.py test`
- Pytest:
  `pytest`

## Scaling guidance for 1000 concurrent users

- Deploy behind Nginx with multiple Gunicorn/Uvicorn workers on Linux.
- Keep `DEBUG=False`, serve static files via CDN/object storage, and use environment variables for secrets.
- Use MySQL connection reuse (`CONN_MAX_AGE`) and add Redis for caching/session storage in production.
- Offload email sending to a background worker for higher login throughput.
