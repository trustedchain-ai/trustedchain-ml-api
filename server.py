"""
TrustedChain HTTP Server - Admin Console & Telemetry API

Simple HTTP server for admin authentication, telemetry tracking,
contact form storage, and secure file uploads.

Security features:
- Token-based authentication for protected endpoints
- File uploads are zipped and quarantined
- No public links to uploaded files
- Input sanitization and validation

Compatible with Python 3.13+ (no cgi module required)
"""

import base64
import json
import os
import re
import uuid
import urllib.request
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, unquote, parse_qs
from zipfile import ZipFile, ZIP_DEFLATED

import joblib
import pandas as pd
import numpy as np

# Configuration
BASE_DIR = Path(__file__).parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True, mode=0o700)

# In-memory storage (for demo purposes - use database in production)
STATS = {
    "visits": 0,
    "clicks": 0,
    "sources": {},
}

CONTACTS = []
TOKENS = set()

# Default credentials (CHANGE IN PRODUCTION)
ADMIN_USERNAME = os.getenv("TRUSTCHAIN_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("TRUSTCHAIN_ADMIN_PASS", "admin")

# Model API configuration
MODEL_DIR = BASE_DIR / "models"
MODEL_DIR.mkdir(exist_ok=True)
MODEL_FILES = {
    "lightgbm": MODEL_DIR / "lightgbm_model.joblib",
    "lightgbm_fast": MODEL_DIR / "lightgbm_fast.joblib",
    "xgboost": MODEL_DIR / "xgboost_model.joblib",
}
MODEL_CACHE = {}
FEATURE_ENCODERS = {}
FEATURE_METADATA_PATH = MODEL_DIR / "feature_metadata.json"
LABEL_MAP_PATH = MODEL_DIR / "label_map.json"
LABEL_MAP_JOBLIB_PATH = MODEL_DIR / "label_map.joblib"
FEATURE_ENCODERS_PATH = MODEL_DIR / "feature_encoders.joblib"
FEATURE_METADATA = {}
# Core + selective features for balanced speed/accuracy
FEATURE_COLUMNS = [
    # Core security features (always fast)
    "signature_hash_algo",
    "signature_key_algo",
    "public_key_algo",
    "public_key_size",
    "can_issue",
    "pathlen",
    "has_roca",
    # Additional trust indicators (optional, still fast)
    "common_name",
    "issuer_dn",
    "not_after",
    "eku",
    "san",
]
# Full feature set loaded from metadata at startup
FULL_FEATURE_COLUMNS = []
LABEL_MAP = {
    0: "benign",
    1: "suspicious",
    2: "malicious",
}

MODEL_RELEASE_TAG = os.getenv("TRUSTCHAIN_MODEL_RELEASE_TAG", "")
MODEL_RELEASE_REPO = os.getenv("TRUSTCHAIN_MODEL_RELEASE_REPO", "a7mdalassaf/TrustChain")
MODEL_RELEASE_TOKEN = os.getenv("GITHUB_TOKEN", "")
MODEL_API_TOKEN = os.getenv("TRUSTCHAIN_API_TOKEN", "")
USE_FAST_MODEL = os.getenv("TRUSTCHAIN_USE_FAST_MODEL", "").lower() in {"1", "true", "yes"}
REMOTE_PREDICT_URL = os.getenv("TRUSTCHAIN_REMOTE_PREDICT_URL", "")

def _download_release_asset(asset_name: str, target_path: Path):
    if not MODEL_RELEASE_TAG or not MODEL_RELEASE_TOKEN:
        return False
    api_url = f"https://api.github.com/repos/{MODEL_RELEASE_REPO}/releases/tags/{MODEL_RELEASE_TAG}"
    req = urllib.request.Request(api_url)
    req.add_header("Authorization", f"token {MODEL_RELEASE_TOKEN}")
    req.add_header("Accept", "application/vnd.github+json")
    with urllib.request.urlopen(req, timeout=30) as resp:
        release_data = json.loads(resp.read().decode("utf-8"))
    assets = release_data.get("assets", [])
    asset = next((a for a in assets if a.get("name") == asset_name), None)
    if not asset:
        return False
    download_url = asset.get("url")
    if not download_url:
        return False
    req = urllib.request.Request(download_url)
    req.add_header("Authorization", f"token {MODEL_RELEASE_TOKEN}")
    req.add_header("Accept", "application/octet-stream")
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(req, timeout=120) as resp, open(target_path, "wb") as f:
        while True:
            chunk = resp.read(8 * 1024 * 1024)
            if not chunk:
                break
            f.write(chunk)
    return target_path.exists()

def _ensure_model_assets():
    for name, model_path in MODEL_FILES.items():
        if model_path.exists():
            continue
        _download_release_asset(model_path.name, model_path)
    if FEATURE_METADATA_PATH.exists() is False:
        _download_release_asset(FEATURE_METADATA_PATH.name, FEATURE_METADATA_PATH)
    if LABEL_MAP_PATH.exists() is False:
        _download_release_asset(LABEL_MAP_PATH.name, LABEL_MAP_PATH)

def _load_feature_metadata():
    global FEATURE_METADATA, LABEL_MAP, FEATURE_ENCODERS
    # Don't overwrite FEATURE_COLUMNS - it's hardcoded for our trained model
    if FEATURE_METADATA_PATH.exists():
        try:
            FEATURE_METADATA = json.loads(FEATURE_METADATA_PATH.read_text())
        except Exception as exc:
            print(f"Failed to load feature metadata: {exc}")
    
    # Try loading label map from joblib first (new format)
    if LABEL_MAP_JOBLIB_PATH.exists():
        try:
            LABEL_MAP = joblib.load(LABEL_MAP_JOBLIB_PATH)
            print(f"Loaded label map: {LABEL_MAP}")
        except Exception as exc:
            print(f"Failed to load label map (joblib): {exc}")
    elif LABEL_MAP_PATH.exists():
        try:
            label_map_raw = json.loads(LABEL_MAP_PATH.read_text())
            # label_map stored as {label: id}
            LABEL_MAP = {int(v): str(k) for k, v in label_map_raw.items()}
        except Exception as exc:
            print(f"Failed to load label map: {exc}")
    
    # Load feature encoders if available
    if FEATURE_ENCODERS_PATH.exists():
        try:
            FEATURE_ENCODERS = joblib.load(FEATURE_ENCODERS_PATH)
            print(f"Loaded feature encoders for {len(FEATURE_ENCODERS)} features")
        except Exception as exc:
            print(f"Failed to load feature encoders: {exc}")

_load_feature_metadata()

def _sanitize_filename(name: str) -> str:
    """
    Sanitize filename to prevent directory traversal and invalid characters.

    Args:
        name: Original filename

    Returns:
        Safe filename with only alphanumeric, underscore, dash, and dot
    """
    # Remove path components and invalid characters
    clean = re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("._")
    # Ensure we have a filename
    return clean or "sample.bin"


def _parse_multipart(body: bytes, boundary: str) -> dict:
    """
    Simple multipart/form-data parser.

    Args:
        body: Request body bytes
        boundary: Multipart boundary string

    Returns:
        Dictionary of form fields
    """
    fields = {}
    parts = body.split(f"--{boundary}".encode())

    for part in parts[1:-1]:  # Skip first and last (empty boundary markers)
        if not part.strip():
            continue

        # Split headers and content
        parts_split = part.split(b"\r\n\r\n", 1)
        if len(parts_split) != 2:
            continue

        headers_raw, content = parts_split
        headers = {}

        # Parse headers
        for header_line in headers_raw.split(b"\r\n"):
            if b":" in header_line:
                key, value = header_line.split(b":", 1)
                headers[key.strip().decode("utf-8").lower()] = value.strip().decode("utf-8")

        # Extract field name from Content-Disposition
        content_disposition = headers.get("content-disposition", "")
        if "name=" in content_disposition:
            name_match = re.search(r'name="([^"]+)"', content_disposition)
            if name_match:
                field_name = name_match.group(1)

                # Check if this is a file upload
                if "filename=" in content_disposition:
                    filename_match = re.search(r'filename="([^"]+)"', content_disposition)
                    if filename_match:
                        filename = filename_match.group(1)
                        fields[field_name] = {"filename": filename, "content": content}
                else:
                    # Regular form field
                    fields[field_name] = content.decode("utf-8", errors="ignore")

    return fields


def _decode_basic_auth(header_value: str):
    if not header_value or not header_value.lower().startswith("basic "):
        return None, None
    try:
        encoded = header_value.split(" ", 1)[1]
        decoded = base64.b64decode(encoded).decode("utf-8")
        username, password = decoded.split(":", 1)
        return username, password
    except Exception:
        return None, None


def _is_model_authorized(headers) -> bool:
    username, password = _decode_basic_auth(headers.get("Authorization", ""))
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return True
    if MODEL_API_TOKEN:
        token = headers.get("X-API-Token", "")
        return token == MODEL_API_TOKEN
    return False


def _load_model(name: str):
    name = name.lower().strip()
    if name not in MODEL_FILES:
        return None
    if name in MODEL_CACHE:
        return MODEL_CACHE[name]
    model_path = MODEL_FILES[name]
    if not model_path.exists():
        return None
    MODEL_CACHE[name] = joblib.load(model_path)
    return MODEL_CACHE[name]


class TrustedChainHandler(SimpleHTTPRequestHandler):
    """HTTP request handler for TrustedChain server."""

    server_version = "TrustedChain/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args):
        """Override to reduce log noise while keeping important info."""
        # Suppress directory listing and favicon requests
        msg = format % args
        if "code 404" in msg and ("favicon.ico" in msg or "directory" in msg):
            return
        print(self.address_string(), "-", msg)

    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)
        path = unquote(parsed.path)

        # Security: Block direct access to upload directory
        if path.startswith("/uploads"):
            return self._forbidden("Access to upload directory is forbidden")

        # Admin overview endpoint
        if parsed.path == "/api/admin/overview":
            return self._handle_admin_overview()

        if parsed.path == "/api/models":
            return self._handle_models()

        # Serve static files
        return super().do_GET()

    def do_POST(self):
        """Handle POST requests."""
        parsed = urlparse(self.path)

        # Route to appropriate handler
        handlers = {
            "/api/upload": self._handle_upload,
            "/api/login": self._handle_login,
            "/api/visit": self._handle_visit,
            "/api/click": self._handle_click,
            "/api/contact": self._handle_contact,
            "/api/predict": self._handle_predict,
        }

        handler = handlers.get(parsed.path)
        if handler:
            return handler()

        self._not_found(f"Unknown endpoint: {parsed.path}")

    def _is_authorized(self) -> bool:
        """Check if request has valid Bearer token."""
        auth_header = self.headers.get("Authorization", "")
        token = auth_header.replace("Bearer ", "").strip()
        return token in TOKENS

    def _handle_upload(self):
        """Handle secure file upload."""
        # Require authentication
        if not self._is_authorized():
            return self._unauthorized("Authentication required for file upload")

        # Validate content type
        ctype = self.headers.get("content-type", "")
        if not ctype.startswith("multipart/form-data"):
            return self._bad_request("Content-Type must be multipart/form-data")

        # Extract boundary
        boundary_match = re.search(r'boundary=([^;\s]+)', ctype)
        if not boundary_match:
            return self._bad_request("Invalid boundary in Content-Type")

        boundary = boundary_match.group(1)

        # Read request body
        content_length = int(self.headers.get("content-length", 0))
        body = self.rfile.read(content_length)

        # Parse multipart form
        try:
            fields = _parse_multipart(body, boundary)
        except Exception as exc:
            print(f"Failed to parse multipart form: {exc}")
            return self._bad_request("Failed to parse form data")

        # Extract file
        file_field = fields.get("file")
        if not file_field or not isinstance(file_field, dict):
            return self._bad_request("No file provided")

        filename = file_field.get("filename", "sample.bin")
        content = file_field.get("content", b"")

        if not content:
            return self._bad_request("Empty file provided")

        # Generate secure filename and zip it
        safe_name = _sanitize_filename(filename)
        token = uuid.uuid4().hex
        zip_name = f"{token}_{safe_name}.zip"
        zip_path = UPLOAD_DIR / zip_name

        try:
            # Read, zip, and store file
            with ZipFile(zip_path, mode="w", compression=ZIP_DEFLATED) as zf:
                zf.writestr(safe_name, content)

            print(f"File uploaded and quarantined: {zip_name} ({len(content)} bytes)")

            # Return response (no public link - security by design)
            response = {
                "status": "stored",
                "token": token,
                "message": "Sample received, compressed, and quarantined. Link hidden by design."
            }
            return self._send_json(response, HTTPStatus.OK)

        except Exception as exc:
            print(f"Failed to store uploaded file: {exc}")
            return self._internal_error("Failed to store file")

    def _handle_login(self):
        """Handle admin login."""
        try:
            # Read and parse request body
            content_length = int(self.headers.get("content-length", 0))
            body = self.rfile.read(content_length)
            data = json.loads(body or "{}")
        except (ValueError, json.JSONDecodeError):
            return self._bad_request("Invalid JSON")

        # Validate credentials
        username = data.get("username")
        password = data.get("password")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            # Generate and store token
            token = uuid.uuid4().hex
            TOKENS.add(token)
            print(f"Admin login successful (tokens: {len(TOKENS)})")
            return self._send_json({"token": token}, HTTPStatus.OK)

        print(f"Failed login attempt: username={username}")
        return self._unauthorized("Invalid credentials")

    def _handle_visit(self):
        """Handle page visit tracking (telemetry)."""
        STATS["visits"] += 1

        # Track source (referer or provided in body)
        source = self.headers.get("Referer") or "direct"
        try:
            content_length = int(self.headers.get("content-length", 0))
            body = self.rfile.read(content_length)
            data = json.loads(body or "{}")
            source = data.get("source") or source
        except Exception:
            pass

        STATS["sources"][source] = STATS["sources"].get(source, 0) + 1
        return self._send_json({"status": "ok"})

    def _handle_click(self):
        """Handle button/link click tracking (telemetry)."""
        STATS["clicks"] += 1
        return self._send_json({"status": "ok"})

    def _handle_contact(self):
        """Handle contact form submission."""
        try:
            # Read and parse request body
            content_length = int(self.headers.get("content-length", 0))
            body = self.rfile.read(content_length)
            data = json.loads(body or "{}")

            # Validate required fields
            name = data.get("name", "").strip()
            email = data.get("email", "").strip()
            subject = data.get("subject", "").strip()
            message = data.get("message", "").strip()

            if not all([name, email, subject, message]):
                return self._bad_request("All fields are required")

            # Store contact submission
            CONTACTS.append({
                "name": name,
                "email": email,
                "subject": subject,
                "message": message,
                "timestamp": __import__("datetime").datetime.now().isoformat()
            })

            print(f"Contact form submission from {email}: {subject}")
            return self._send_json({"status": "received"})

        except (ValueError, json.JSONDecodeError):
            return self._bad_request("Invalid JSON")

    def _handle_models(self):
        """Return available models."""
        if not _is_model_authorized(self.headers):
            return self._unauthorized("Authentication required")

        _ensure_model_assets()
        _load_feature_metadata()

        available = [name for name, path in MODEL_FILES.items() if path.exists()]
        payload = {
            "available": available,
            "expected_features": FEATURE_COLUMNS,
            "feature_metadata": FEATURE_METADATA,
            "labels": LABEL_MAP,
        }
        return self._send_json(payload)

    def _handle_predict(self):
        """Predict label using selected model."""
        if not _is_model_authorized(self.headers):
            return self._unauthorized("Authentication required")

        try:
            content_length = int(self.headers.get("content-length", 0))
            body = self.rfile.read(content_length)
            data = json.loads(body or "{}")
        except (ValueError, json.JSONDecodeError):
            return self._bad_request("Invalid JSON")

        # If remote prediction URL is set, forward request
        if REMOTE_PREDICT_URL:
            try:
                req = urllib.request.Request(
                    REMOTE_PREDICT_URL,
                    data=json.dumps(data).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    result = json.loads(resp.read().decode())
                    return self._send_json(result)
            except Exception as exc:
                print(f"Remote prediction failed: {exc}")
                return self._internal_error("Remote prediction service unavailable")

        model_name = (data.get("model") or "lightgbm").lower()
        if USE_FAST_MODEL and model_name == "lightgbm":
            model_name = "lightgbm_fast"
        _ensure_model_assets()
        _load_feature_metadata()
        model = _load_model(model_name)
        if model is None:
            return self._send_json(
                {"error": "Model not available", "model": model_name},
                HTTPStatus.SERVICE_UNAVAILABLE,
            )

        features = data.get("features") or {}
        if not isinstance(features, dict):
            return self._bad_request("Features must be an object")

        # Fill missing features with defaults and encode
        row = {}
        meta = FEATURE_METADATA.get("features", {}) if isinstance(FEATURE_METADATA, dict) else {}
        for col in FEATURE_COLUMNS:
            value = features.get(col, "")
            
            # Apply default if missing
            if value == "" or value is None:
                col_meta = meta.get(col, {}) if isinstance(meta, dict) else {}
                if col_meta.get("type") == "numeric":
                    value = 0
                else:
                    value = ""
            
            # Encode categorical features if encoder exists
            if col in FEATURE_ENCODERS:
                encoder = FEATURE_ENCODERS[col]
                try:
                    # Handle unseen categories by using first class
                    value_str = str(value)
                    if value_str not in encoder.classes_:
                        value = 0  # Default encoding for unseen values
                    else:
                        value = encoder.transform([value_str])[0]
                except Exception:
                    value = 0
            
            row[col] = value

        # Create DataFrame with only the features used in training
        df = pd.DataFrame([row])[FEATURE_COLUMNS]
        
        # Ensure all columns are numeric (required by LightGBM)
        for col in df.columns:
            if df[col].dtype == 'object':
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(int)

        try:
            # Get prediction
            pred_raw = model.predict(df)
            
            # Normalize to 1D array
            if isinstance(pred_raw, np.ndarray):
                if len(pred_raw.shape) == 2:
                    # 2D array - could be one-hot or probabilities
                    pred_vec = pred_raw[0]
                    pred = int(np.argmax(pred_vec))
                    probs = pred_vec
                else:
                    # 1D array - single prediction
                    pred = int(pred_raw[0])
                    probs = None
            else:
                pred = int(pred_raw)
                probs = None

            response = {
                "model": model_name,
                "label_id": pred,
                "label": LABEL_MAP.get(pred, str(pred)),
            }
            
            if probs is not None:
                response["probabilities"] = {
                    LABEL_MAP.get(i, str(i)): float(p) for i, p in enumerate(probs)
                }
            
            return self._send_json(response)
        except Exception as exc:
            import traceback
            traceback.print_exc()
            print(f"Prediction failed: {exc}")
            return self._internal_error("Prediction failed")

    def _handle_admin_overview(self):
        """Handle admin dashboard data request."""
        # Require authentication
        if not self._is_authorized():
            return self._unauthorized("Authentication required")

        # Collect upload metadata (not content)
        uploads = []
        for file in sorted(UPLOAD_DIR.glob("*.zip")):
            stats = file.stat()
            uploads.append({
                "name": file.name,
                "size": stats.st_size,
                "modified": stats.st_mtime
            })

        # Collect sources
        sources = [{"source": key, "count": value}
                   for key, value in STATS["sources"].items()]

        # Build response
        payload = {
            "visits": STATS["visits"],
            "clicks": STATS["clicks"],
            "uploads": uploads,
            "sources": sources,
            "contacts": CONTACTS,
        }

        return self._send_json(payload)

    def _send_json(self, data: dict, status: HTTPStatus = HTTPStatus.OK):
        """Send JSON response."""
        try:
            payload = json.dumps(data).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(payload)
        except Exception as exc:
            print(f"Failed to send JSON response: {exc}")

    def _bad_request(self, message: str = "Bad request"):
        """Send 400 Bad Request response."""
        return self.send_error(HTTPStatus.BAD_REQUEST, message)

    def _unauthorized(self, message: str = "Unauthorized"):
        """Send 401 Unauthorized response."""
        return self.send_error(HTTPStatus.UNAUTHORIZED, message)

    def _forbidden(self, message: str = "Forbidden"):
        """Send 403 Forbidden response."""
        return self.send_error(HTTPStatus.FORBIDDEN, message)

    def _not_found(self, message: str = "Not found"):
        """Send 404 Not Found response."""
        return self.send_error(HTTPStatus.NOT_FOUND, message)

    def _internal_error(self, message: str = "Internal server error"):
        """Send 500 Internal Server Error response."""
        return self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, message)

    def list_directory(self, path):
        """Disable directory listing for security."""
        self.send_error(HTTPStatus.FORBIDDEN, "Directory listing is not allowed")
        return None


def _warmup_models():
    """Preload models into cache for faster first request"""
    print("Warming up models...")
    _ensure_model_assets()
    _load_feature_metadata()
    model_names = list(MODEL_FILES.keys())
    if USE_FAST_MODEL:
        model_names = ["lightgbm_fast"]
    for model_name in model_names:
        model_path = MODEL_FILES.get(model_name)
        if model_path and model_path.exists():
            print(f"  Loading {model_name}...")
            _load_model(model_name)
            print(f"  ✓ {model_name} ready")
    print("✓ Model warmup complete\n")


def run(host: str = "0.0.0.0", port: int = 4173):
    """
    Run TrustedChain HTTP server.

    Args:
        host: Host to bind to
        port: Port to listen on
    """
    # Warmup models at startup
    _warmup_models()
    
    server_address = (host, port)
    httpd = ThreadingHTTPServer(server_address, TrustedChainHandler)

    print(f"""
╔═══════════════════════════════════════════════════════╗
║           TrustedChain Admin & Telemetry Server             ║
╠═══════════════════════════════════════════════════════╣
║  Host: {host:<48} ║
║  Port: {port:<48} ║
║  URL:  http://localhost:{port}/       ║
╠═══════════════════════════════════════════════════════╣
║  Endpoints:                                            ║
║  GET  /              - Landing page                        ║
║  GET  /admin.html    - Admin console                      ║
║  POST /api/login     - Get auth token                     ║
║  POST /api/upload    - Upload file (protected)            ║
║  POST /api/visit     - Log page visit                    ║
║  POST /api/click     - Log button click                  ║
║  POST /api/contact   - Contact form submission            ║
║  GET  /api/admin/overview - Admin dashboard data         ║
╚═══════════════════════════════════════════════════════╝
    """)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    # Allow environment variable overrides
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "4173"))

    run(host=host, port=port)
