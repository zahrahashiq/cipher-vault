import secrets
from typing import Dict, Optional
from flask import Flask, flash, redirect, render_template, request, session, url_for, jsonify
import time
from functools import wraps
import vault_store

app = Flask(__name__)

#Secret key used in Flask to sign session cookies
app.secret_key = secrets.token_hex(32)

#autolock the vault after inactivity in seconds
AUTO_LOCK_SECONDS = 300  # 5 minutes

#in-memory keyring = session token, derviles ecryption key
# encryption key never stored in user's session cookie
KEYRING: Dict[str, bytes] = {}

#record of user's most recent activity on the app
def _touch_activity():
    session["last_activity"] = time.time()

# if session has been inactive > than AUTOLOCKSECONDS
# if longer, return true
def _is_timed_out() -> bool:
    last = session.get("last_activity")
    if not last:
        return False
    return (time.time() - float(last)) > AUTO_LOCK_SECONDS

#Lock the vault for the current session
# remove token and wipe activity time stamp
# remove derived key from keyring 
def _force_lock():
    token = session.pop("token", None)
    session.pop("last_activity", None)
    if token:
        KEYRING.pop(token, None)

#Blocks access until vault is unlocked
#API endpoints - return JSON + 401 so frontend can react
# Redirect to unlock 
def require_unlocked(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        is_api = request.path.startswith("/api/")

        #Must have session token that maps to an in-memory key
        token = session.get("token")
        if not token or token not in KEYRING:
            if is_api:
                return jsonify({"error": "locked"}), 401
            return redirect(url_for("unlock"))

        #auto lock if user in inactive for too long
        if _is_timed_out():
            _force_lock()
            if is_api:
                return jsonify({"error": "auto_locked"}), 401
            flash("Auto-locked due to inactivity.", "error")
            return redirect(url_for("unlock"))

        #Update timestamp for real user actions
        # no not extend session
        if request.path != "/api/ping":
            _touch_activity()
        return view_func(*args, **kwargs)

    return wrapper

#Return derived encryption key for the current session
#return none if locked
#The session only stores a random token, the key is server-side in KEYRING 
def _get_key() -> Optional[bytes]:
    token = session.get("token")
    if not token:
        return None
    return KEYRING.get(token)

#Send user to the starting page based on the vaults state
@app.route("/")
def home():
    if not vault_store.vault_exists():
        return redirect(url_for("setup"))
    if not _get_key():
        return redirect(url_for("unlock"))
    return redirect(url_for("vault"))

#endpoint used by the frontend to detect a locked session
@app.route("/api/ping")
@require_unlocked
def api_ping():
    return jsonify({"ok": True})


#Create a new vault and set the master password (when running for the first time)
@app.route("/setup", methods=["GET", "POST"])
def setup():
    if vault_store.vault_exists():
        return redirect(url_for("unlock"))

    if request.method == "POST":
        pw1 = request.form.get("master1", "")
        pw2 = request.form.get("master2", "")

        #basic policy for the master password
        if len(pw1) < 8:
            flash("Use at least 8 characters for your master password.", "error")
            return render_template("setup.html")

        if pw1 != pw2:
            flash("Passwords don't match.", "error")
            return render_template("setup.html")

        vault_store.create_new_vault(pw1)
        flash("Vault created. Now unlock it.", "ok")
        return redirect(url_for("unlock"))

    return render_template("setup.html")

#Unlock the vault by deriving the encryption key from master password
@app.route("/unlock", methods=["GET", "POST"])
def unlock():
    if not vault_store.vault_exists():
        return redirect(url_for("setup"))

    if request.method == "POST":
        master = request.form.get("master", "")
        try:
            #derive key using vault_store
            key, _ = vault_store.unlock_with_password(master)
        #generic
        #avoid mentioning whether vault exists or was tampered with specfically
        except Exception:
            flash("Wrong password OR vault was tampered with.", "error")
            return render_template("unlock.html")

        #create a random session token and store key server-side
        token = secrets.token_urlsafe(24)
        session["token"] = token
        KEYRING[token] = key
        _touch_activity()

        flash("Vault unlocked.", "ok")
        return redirect(url_for("vault"))

    return render_template("unlock.html")

#Display list of entries (passwords fetched when demaneded via API)
@app.route("/vault")
@require_unlocked
def vault():
    key = _get_key()
    if not key:
        return redirect(url_for("unlock"))

    data = vault_store.load_with_key(key)
    entries = vault_store.list_entries(data)
    return render_template("vault.html", entries=entries)

#Return single password using index when revealing or copying to clipboard
@app.route("/api/password/<int:index>")
@require_unlocked
def api_password(index: int):
    key = _get_key()
    if not key:
        return jsonify({"error": "locked"}), 401

    data = vault_store.load_with_key(key)
    entries = vault_store.list_entries(data)

    if index < 0 or index >= len(entries):
        return jsonify({"error": "not_found"}), 404

    return jsonify({"password": entries[index]["password"]})

#add new vault entry (site, username, password)
@app.route("/add", methods=["GET", "POST"])
@require_unlocked
def add():
    key = _get_key()
    if not key:
        return redirect(url_for("unlock"))

    if request.method == "POST":
        site = request.form.get("site", "")
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        data = vault_store.load_with_key(key)
        vault_store.add_entry(data, site, username, password)
        vault_store.save_with_key(key, data)

        flash("Entry added.", "ok")
        return redirect(url_for("vault"))

    return render_template("add.html")

#Manual lock - clears session and removes key from memory
@app.route("/lock")
def lock():
    _force_lock()
    flash("Vault locked.", "ok")
    return redirect(url_for("unlock"))


if __name__ == "__main__":
    #debug for local demons, should be off for production deployment
    app.run(debug=True)
