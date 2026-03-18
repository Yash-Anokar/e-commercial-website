# Railway Deployment

## 1. Push the project

Push this folder to a GitHub repository.

## 2. Create the Railway project

1. In Railway, create a new project from GitHub.
2. Select this repository.
3. Add a MySQL database service to the same project.

## 3. Set environment variables

Set these variables in Railway for the web service:

- `SECRET_KEY`

You do not need to manually add the database credentials if Railway already exposes:

- `MYSQLHOST`
- `MYSQLPORT`
- `MYSQLUSER`
- `MYSQLPASSWORD`
- `MYSQLDATABASE`

The app is already configured to read either `DB_*` variables or Railway's `MYSQL*` variables.

## 4. Deploy settings

- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app --bind 0.0.0.0:$PORT`

## 5. Database notes

On first boot the app will:

- create the database if needed
- create required tables if missing
- create the default admin user if it does not exist

## 6. After deploy

1. Open the Railway public URL.
2. Test home page, product page, cart, checkout, orders, and admin.
3. Change the default admin password immediately.
