# Django Encrypted Posts Project

A secure Django web application for user registration, profile management, and creating/viewing AES-encrypted posts. All sensitive user information (emails, names, profile pictures, posts) is encrypted before storing in the database.

---

## Features

- **User Authentication**
  - Signup, login, logout
  - Superuser access for administration

- **User Profiles**
  - Profile picture upload (encrypted)
  - Encrypted storage of email, first name, and last name

- **Encrypted Posts**
  - Create posts that are AES-encrypted
  - View encrypted and decrypted content in the frontend

- **Security**
  - AES encryption for sensitive data
  - Centralized key management (`encryption_key.key`)
  - Passwords hashed using Django's `make_password`

- **Other Pages**
  - Contact form
  - About page
  - Operators page

---

## Installation

1. **Clone the repository**

```bash
git clone <repository_url>
cd <project_folder>

Create a virtual environment
python -m venv venv
venv\Scripts\activate   # Windows
source venv/bin/activate # Linux / macOS
Install dependencies
pip install -r requirements.txt
Run migrations
python manage.py makemigrations
python manage.py migrate
Create a superuser (optional)
python manage.py createsuperuser
Start the server
python manage.py runserver
