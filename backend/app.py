"""
app.py
Flask application entry point.
Registers Tejas's blueprints. Vanshika and Akhil register theirs here too.
"""

from flask import Flask
from flask_cors import CORS

from database.models import init_db
from auth_rbac.roles import load_permissions
from policy_engine.policy_loader import load_policies, import_from_file
from routes.auth_routes import auth_bp, user_bp, policy_bp

# Vanshika imports (uncomment when her work is ready):

from routes.syscall_routes import syscall_bp
from routes.log_routes import log_bp

# Akhil imports (uncomment when his work is ready):
# from routes.dashboard_routes import dashboard_bp


def create_app():
    app = Flask(__name__)
    CORS(app)

    # Initialize DB and in-memory caches
    init_db()
    load_permissions()
    load_policies()

    # Optionally sync policies from JSON file on startup
    # Note: Ensure the path is correct relative to where you run the app (backend/)
    import_from_file("policy_engine/policy_rules.json")

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(policy_bp)

    app.register_blueprint(syscall_bp)
    app.register_blueprint(log_bp)
    # app.register_blueprint(dashboard_bp) ← Akhil

    return app


if __name__ == "__main__":
    app = create_app()
    from config import DEBUG, PORT

    app.run(debug=DEBUG, port=PORT)
