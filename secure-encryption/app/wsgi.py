"""Serve the local browser UI and API from one production WSGI endpoint."""
from pathlib import Path
from urllib.parse import urlsplit

from flask import Response, jsonify, request, send_from_directory
from app import app

ROOT = Path(__file__).resolve().parent


@app.before_request
def reject_cross_origin_posts():
    origin = request.headers.get('Origin')
    if request.method == 'POST' and origin:
        parsed = urlsplit(origin)
        if parsed.scheme not in ('http', 'https') or parsed.netloc != request.host:
            return jsonify(success=False, message='Cross-origin requests are not allowed.'), 403


@app.after_request
def response_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
    )
    return response


@app.get('/')
def index():
    return send_from_directory(ROOT, 'index.html')


@app.get('/app.js')
def javascript():
    content = (ROOT / 'app.js').read_text()
    content = content.replace('const API = "http://localhost:5000";',
                              'const API = window.location.origin;')
    return Response(content, mimetype='application/javascript')


@app.get('/styles.css')
def stylesheet():
    return send_from_directory(ROOT, 'styles.css')
