from app import create_app
from generate_cert import ensure_cert

app = create_app()

if __name__ == '__main__':
    # Ensure a self-signed certificate exists, then serve the app over HTTPS (TLS).
    # The hardened copy runs on https://localhost:5001 — the original is on 5000.
    # debug=True restarts the server automatically when a file is saved.
    # Never use debug=True in a real production deployment.
    cert_file, key_file = ensure_cert()
    app.run(debug=True, port=5001, ssl_context=(cert_file, key_file))
