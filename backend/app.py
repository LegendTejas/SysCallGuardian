from flask import Flask
from flask_cors import CORS

from database.models             import init_db
from auth_rbac.roles             import load_permissions
from policy_engine.policy_loader import load_policies, import_from_file
from routes.auth_routes          import auth_bp, user_bp, policy_bp
from routes.syscall_routes       import syscall_bp
from routes.log_routes           import log_bp


def create_app():
    # Configure Flask to serve the frontend directory as static files
    import os
    frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend'))
    app = Flask(__name__, static_folder=frontend_dir, static_url_path='')
    CORS(app)

    init_db()
    load_permissions()
    load_policies()
    import_from_file("policies/access_policy.json")

    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(policy_bp)
    app.register_blueprint(syscall_bp)
    app.register_blueprint(log_bp)

    @app.route("/")
    def serve_index():
        return app.send_static_file('index.html')
    return app


if __name__ == "__main__":
    app = create_app()
    from config import DEBUG, PORT
    app.run(debug=DEBUG, port=PORT)
