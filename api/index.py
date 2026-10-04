"""
api/index.py
------------
Flask Application หลักของระบบร้านอาหาร (Restaurant Management System)
Deploy บน Vercel (Serverless Function)
"""

import os
import sys
from datetime import datetime
from functools import wraps
from typing import Any, Callable, Dict, List, Optional

# โหลด .env อัตโนมัติ (สำหรับ dev)
try:
    from dotenv import load_dotenv  # type: ignore
    _env_path: str = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if os.path.exists(_env_path):
        load_dotenv(_env_path)
except ImportError:
    pass  # python-dotenv ไม่ได้ติดตั้ง — ใช้ ENV ปกติ

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)


# ===============================================================
# 1) Path & Module Import
# ===============================================================
_THIS_FILE: str = os.path.abspath(__file__)
_API_DIR: str = os.path.dirname(_THIS_FILE)
_PROJECT_ROOT: str = os.path.dirname(_API_DIR)

for _p in (_PROJECT_ROOT, _API_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from modules import restaurant as resto  # type: ignore
    from modules import db as db_module      # type: ignore
except ImportError:
    try:
        import restaurant as resto           # type: ignore
    except ImportError:
        resto = None
    try:
        import db as db_module               # type: ignore
    except ImportError:
        db_module = None


# ===============================================================
# 2) Flask App
# ===============================================================
app = Flask(
    __name__,
    template_folder=os.path.join(_PROJECT_ROOT, "templates"),
    static_folder=os.path.join(_PROJECT_ROOT, "static"),
)

# ===============================================================
# SECURITY: Secret Key Management
# ===============================================================
def _get_secret_key() -> str:
    """
    ดึง secret key ที่ปลอดภัย
    - Production: บังคับให้ตั้ง ENV SECRET_KEY
    - Development: สร้าง random key ต่อ session (unstable แต่ปลอดภัยกว่า hardcode)
    """
    env_key: str = str(os.environ.get("SECRET_KEY", "")).strip()

    if env_key:
        if len(env_key) < 16:
            raise RuntimeError(
                "SECRET_KEY ต้องยาวอย่างน้อย 16 ตัวอักษร "
                "(ปัจจุบัน: " + str(len(env_key)) + ")"
            )
        return env_key

    # ตรวจสอบว่าเป็น production หรือไม่
    is_production: bool = (
        os.environ.get("VERCEL") == "1"
        or os.environ.get("FLASK_ENV") == "production"
        or os.environ.get("ENV") == "production"
    )

    if is_production:
        raise RuntimeError(
            "SECRET_KEY environment variable is REQUIRED in production. "
            "Please set it in Vercel Environment Variables."
        )

    # Development fallback: random key (จะ logout เมื่อ restart)
    import secrets
    dev_key: str = secrets.token_hex(32)
    print("[WARNING] ใช้ development secret key (random) — ควรตั้ง SECRET_KEY ใน .env")
    return dev_key


app.secret_key = _get_secret_key()

# Cookie Security
app.config["SESSION_COOKIE_HTTPONLY"] = True       # JS เข้าถึง cookie ไม่ได้
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"      # กัน CSRF พื้นฐาน
app.config["SESSION_COOKIE_SECURE"] = (            # ✅ C7: HTTPS เท่านั้น (production)
    os.environ.get("VERCEL") == "1"
    or os.environ.get("FLASK_ENV") == "production"
)
app.config["JSON_AS_ASCII"] = False
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = False

# ===============================================================
# SECURITY: CSRF Protection (Custom — ไม่ใช้ library ภายนอก)
# ===============================================================
import secrets as _csrf_secrets


@app.before_request
def _ensure_csrf_token() -> None:
    """สร้าง CSRF token ใหม่ถ้ายังไม่มีใน session"""
    try:
        if "_csrf_token" not in session or not session.get("_csrf_token"):
            session["_csrf_token"] = _csrf_secrets.token_urlsafe(32)
    except Exception:
        pass


def csrf_token() -> str:
    """คืน CSRF token ของ session ปัจจุบัน"""
    try:
        return str(session.get("_csrf_token", ""))
    except Exception:
        return ""


@app.context_processor
def _inject_csrf_token() -> Dict[str, Any]:
    """ทำให้ template เรียก {{ csrf_token() }} ได้"""
    return {"csrf_token": csrf_token}


@app.before_request
def _csrf_protect() -> Any:
    """ตรวจสอบ CSRF token ในทุก POST request"""
    try:
        if request.method != "POST":
            return None

        # ข้าม static
        if (request.endpoint or "").startswith("static"):
            return None

        session_token: str = str(session.get("_csrf_token", ""))
        form_token: str = str(request.form.get("_csrf", ""))

        # ถ้าไม่มี token ในฟอร์มหรือ session → block
        if not session_token or not form_token:
            flash("CSRF token ไม่ถูกต้อง กรุณาลองใหม่อีกครั้ง", "danger")
            return redirect(url_for("login"))

        # เปรียบเทียบแบบ constant-time (กัน timing attack)
        if not _csrf_secrets.compare_digest(session_token, form_token):
            flash("CSRF token ไม่ถูกต้อง กรุณาลองใหม่อีกครั้ง", "danger")
            return redirect(url_for("login"))

        return None
    except Exception:
        flash("เกิดข้อผิดพลาดด้านความปลอดภัย", "danger")
        return redirect(url_for("login"))
# ===============================================================
# 3) Decorators
# ===============================================================
def login_required(view_func: Callable) -> Callable:
    @wraps(view_func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if not session.get("username"):
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapper


def role_required(*allowed_roles: str) -> Callable:
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                if "username" not in session:
                    flash("กรุณาเข้าสู่ระบบก่อนใช้งาน", "warning")
                    return redirect(url_for("login"))

                user_role: str = str(session.get("role", ""))

                if user_role not in ("admin", "staff", "customer"):
                    session.clear()
                    flash("Session ไม่ถูกต้อง กรุณาเข้าสู่ระบบใหม่", "warning")
                    return redirect(url_for("login"))

                if user_role not in allowed_roles:
                    flash("คุณไม่มีสิทธิ์เข้าถึงหน้านี้", "danger")
                    if user_role == "customer":
                        return redirect(url_for("my_table"))
                    return redirect(url_for("tables"))

                return view_func(*args, **kwargs)

            except Exception:
                session.clear()
                flash("เกิดข้อผิดพลาดเรื่องสิทธิ์ กรุณาเข้าสู่ระบบใหม่", "danger")
                return redirect(url_for("login"))
        return wrapper
    return decorator


# ===============================================================
# 4) Helpers
# ===============================================================
def _safe_result(result: Any) -> Dict[str, Any]:
    if isinstance(result, dict) and "success" in result:
        return result
    return {"success": False, "message": "ผลลัพธ์จากระบบไม่ถูกต้อง"}


def _current_user() -> Dict[str, str]:
    return {
        "username": str(session.get("username", "")),
        "role": str(session.get("role", "")),
        "name": str(session.get("name", "")),
    }


def _landing_url_for_role(role: str) -> str:
    if role == "customer":
        if session.get("table_id"):
            return url_for("my_table")
        return url_for("select_table")
    return url_for("tables")


# ===============================================================
# 5) Authentication
# ===============================================================
@app.route("/")
def index() -> Any:
    try:
        if session.get("username"):
            return redirect(_landing_url_for_role(str(session.get("role", ""))))
        return redirect(url_for("login"))
    except Exception:
        return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login() -> Any:
    try:
        if request.method == "GET" and session.get("username"):
            return redirect(_landing_url_for_role(str(session.get("role", ""))))

        if request.method == "POST":
            username: str = str(request.form.get("username", "")).strip()
            password: str = str(request.form.get("password", ""))

            if not username or not password:
                flash("กรุณากรอกชื่อผู้ใช้และรหัสผ่านให้ครบถ้วน", "danger")
                return render_template("login.html", username=username), 200

            if resto is None:
                flash("ระบบ backend ยังไม่พร้อมใช้งาน", "danger")
                return render_template("login.html", username=username), 500

            result: Dict[str, Any] = _safe_result(resto.authenticate_user(username, password))

            if result.get("success"):
                user_data: Dict[str, Any] = result.get("data", {}) or {}
                session.clear()
                session["username"] = user_data.get("username", username)
                session["role"] = user_data.get("role", "customer")
                session["name"] = user_data.get("name", "")
                session.permanent = False

                try:
                    resto.record_log(
                        user_data.get("username", username),
                        user_data.get("role", ""),
                        "login",
                        "เข้าสู่ระบบสำเร็จ",
                    )
                except Exception:
                    pass

                if session.get("role") == "customer":
                    my = resto.get_my_table_info(session.get("username", ""))
                    if my.get("success"):
                        table_data = (my.get("data") or {}).get("table") or {}
                        try:
                            session["table_id"] = int(table_data.get("id", 0))
                        except (ValueError, TypeError):
                            session.pop("table_id", None)

                flash(f"ยินดีต้อนรับ {session.get('name') or username}", "success")
                return redirect(_landing_url_for_role(str(session.get("role", ""))))

            flash(result.get("message", "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"), "danger")
            return render_template("login.html", username=username), 200

        return render_template("login.html", username="")

    except Exception:
        flash("เกิดข้อผิดพลาดในการเข้าสู่ระบบ", "danger")
        return render_template("login.html", username=""), 200


@app.route("/register", methods=["GET", "POST"])
def register() -> Any:
    try:
        if request.method == "GET" and session.get("username"):
            return redirect(_landing_url_for_role(str(session.get("role", ""))))

        if request.method == "POST":
            username: str = str(request.form.get("username", "")).strip()
            password: str = str(request.form.get("password", ""))
            confirm: str = str(request.form.get("confirm_password", ""))
            name: str = str(request.form.get("name", "")).strip()

            if not username or not password or not name:
                flash("กรุณากรอกข้อมูลให้ครบทุกช่อง", "danger")
                return render_template("register.html", username=username, name=name), 200
            if len(username) < 3:
                flash("ชื่อผู้ใช้ต้องมีความยาวอย่างน้อย 3 ตัวอักษร", "danger")
                return render_template("register.html", username=username, name=name), 200
            if len(password) < 4:
                flash("รหัสผ่านต้องมีความยาวอย่างน้อย 4 ตัวอักษร", "danger")
                return render_template("register.html", username=username, name=name), 200
            if password != confirm:
                flash("รหัสผ่านทั้งสองช่องไม่ตรงกัน", "danger")
                return render_template("register.html", username=username, name=name), 200

            if resto is None:
                flash("ระบบ backend ยังไม่พร้อมใช้งาน", "danger")
                return render_template("register.html", username=username, name=name), 500

            result: Dict[str, Any] = _safe_result(
                resto.register_user(username, password, name, role="customer")
            )

            if result.get("success"):
                flash(result.get("message", "สมัครสมาชิกสำเร็จ"), "success")
                return redirect(url_for("login"))

            flash(result.get("message", "ไม่สามารถสมัครสมาชิกได้"), "danger")
            return render_template("register.html", username=username, name=name), 200

        return render_template("register.html", username="", name="")

    except Exception:
        flash("เกิดข้อผิดพลาดในการสมัครสมาชิก", "danger")
        return render_template("register.html", username="", name=""), 200


@app.route("/logout")
def logout() -> Any:
    try:
        username: str = str(session.get("username", ""))
        role: str = str(session.get("role", ""))

        if username and resto is not None:
            try:
                resto.record_log(username, role, "logout", "ออกจากระบบ")
            except Exception:
                pass

        session.clear()
        flash("ออกจากระบบเรียบร้อยแล้ว", "info")
    except Exception:
        session.clear()
    return redirect(url_for("login"))


@app.route("/reset-session")
def reset_session() -> Any:
    """Emergency: ล้าง session เพื่อปลดล็อกถ้า loop"""
    session.clear()
    flash("ล้าง Session เรียบร้อย กรุณาเข้าสู่ระบบใหม่", "info")
    return redirect(url_for("login"))


# ===============================================================
# 6) Customer: select-table / join / my-table
# ===============================================================
@app.route("/select-table", methods=["GET", "POST"])
@login_required
@role_required("customer")
def select_table() -> Any:
    """หน้าเลือกโต๊ะครั้งแรกของลูกค้า"""
    try:
        if resto is None:
            session.clear()
            flash("ระบบ backend ยังไม่พร้อมใช้งาน", "danger")
            return redirect(url_for("login"))

        # เช็คว่ามีโต๊ะอยู่แล้วหรือยัง
        my = _safe_result(resto.get_my_table_info(session.get("username", "")))
        came_from = str(request.args.get("from", "")).strip()

        # ⚠️ redirect ไป my-table เฉพาะเมื่อไม่ได้มาจาก my-table
        if my.get("success") and came_from != "my-table":
            table_data = (my.get("data") or {}).get("table") or {}
            try:
                session["table_id"] = int(table_data.get("id", 0))
            except (ValueError, TypeError):
                pass
            return redirect(url_for("my_table"))

        # POST: กดเลือกโต๊ะ
        if request.method == "POST":
            table_id_raw: str = str(request.form.get("table_id", "")).strip()
            try:
                table_id: int = int(table_id_raw)
            except (ValueError, TypeError):
                flash("หมายเลขโต๊ะไม่ถูกต้อง", "danger")
                return redirect(url_for("select_table", **{"from": "my-table"}))

            result: Dict[str, Any] = _safe_result(
                resto.assign_table_to_customer(session.get("username", ""), table_id)
            )

            if result.get("success"):
                session["table_id"] = table_id
                flash(result.get("message", "เลือกโต๊ะสำเร็จ"), "success")
                return redirect(url_for("my_table"))

            flash(result.get("message", "ไม่สามารถเลือกโต๊ะได้"), "danger")
            return redirect(url_for("select_table", **{"from": "my-table"}))

        # GET: แสดงโต๊ะ
        tables_data: List[Dict[str, Any]] = []
        if db_module is not None:
            loaded = db_module.load_json("tables.json", default=[])
            if isinstance(loaded, list):
                for t in loaded:
                    if isinstance(t, dict) and str(t.get("status", "")) != "billing":
                        tables_data.append(t)

        return render_template(
            "select-table.html",
            tables=tables_data,
            is_change_mode=False,
            current_table=None,
            user=_current_user(),
        )

    except Exception as e:
        session.clear()
        flash(f"เกิดข้อผิดพลาด: {e} กรุณาเข้าสู่ระบบใหม่", "danger")
        return redirect(url_for("login"))


@app.route("/join", methods=["GET", "POST"])
@login_required
@role_required("customer")
def join_table() -> Any:
    """หน้ากรอกรหัสเชิญเพื่อเข้าร่วมโต๊ะ"""
    try:
        if request.method == "POST":
            invite_code: str = str(request.form.get("invite_code", "")).strip()

            if not invite_code:
                flash("กรุณากรอกรหัสเชิญ", "danger")
                return render_template("join.html", user=_current_user()), 200

            if resto is None:
                flash("ระบบ backend ยังไม่พร้อมใช้งาน", "danger")
                return render_template("join.html", user=_current_user()), 500

            result: Dict[str, Any] = _safe_result(
                resto.join_table_with_code(session.get("username", ""), invite_code)
            )

            if result.get("success"):
                table_data = result.get("data") or {}
                try:
                    session["table_id"] = int(table_data.get("id", 0))
                except (ValueError, TypeError):
                    pass
                flash(result.get("message", "เข้าร่วมโต๊ะสำเร็จ"), "success")
                return redirect(url_for("my_table"))

            flash(result.get("message", "ไม่สามารถเข้าร่วมโต๊ะได้"), "danger")
            return render_template("join.html", user=_current_user()), 200

        return render_template("join.html", user=_current_user())

    except Exception:
        flash("เกิดข้อผิดพลาดในการเข้าร่วมโต๊ะ", "danger")
        return render_template("join.html", user=_current_user()), 200


@app.route("/my-table")
@login_required
@role_required("customer")
def my_table() -> Any:
    """หน้าโต๊ะของฉัน (สำหรับ host + members)"""
    try:
        if resto is None:
            session.clear()
            flash("ระบบ backend ยังไม่พร้อมใช้งาน", "danger")
            return redirect(url_for("login"))

        result: Dict[str, Any] = _safe_result(
            resto.get_my_table_info(session.get("username", ""))
        )

        # ❌ ไม่ redirect — render select-table.html ตรงๆ กัน loop
        if not result.get("success"):
            tables_data: List[Dict[str, Any]] = []
            if db_module is not None:
                loaded = db_module.load_json("tables.json", default=[])
                if isinstance(loaded, list):
                    for t in loaded:
                        if isinstance(t, dict) and str(t.get("status", "")) != "billing":
                            tables_data.append(t)
            flash(result.get("message", "คุณยังไม่ได้เลือกโต๊ะ กรุณาเลือกก่อน"), "info")
            return render_template(
                "select-table.html",
                tables=tables_data,
                is_change_mode=False,
                current_table=None,
                user=_current_user(),
            ), 200

        info: Dict[str, Any] = result.get("data", {}) or {}
        table_data: Dict[str, Any] = info.get("table", {}) or {}

        try:
            session["table_id"] = int(table_data.get("id", 0))
        except (ValueError, TypeError):
            pass

        members: List[str] = list(table_data.get("members") or [])
        users_data: List[Dict[str, Any]] = []
        if db_module is not None:
            loaded_users = db_module.load_json("users.json", default=[])
            if isinstance(loaded_users, list):
                users_data = loaded_users

        user_map: Dict[str, str] = {}
        for u in users_data:
            if isinstance(u, dict):
                uname = str(u.get("username") or "")
                if uname:
                    user_map[uname] = str(u.get("name") or uname)

        member_details: List[Dict[str, str]] = []
        for m in members:
            uname = str(m)
            member_details.append({
                "username": uname,
                "name": user_map.get(uname, uname) or uname,
            })

        return render_template(
            "my-table.html",
            table=table_data,
            is_host=bool(info.get("is_host", False)),
            orders=info.get("orders", []) or [],
            subtotal=info.get("subtotal", 0.0),
            members=member_details,
            invite_code=table_data.get("invite_code"),
            user=_current_user(),
        )

    except Exception as e:
        session.clear()
        flash(f"เกิดข้อผิดพลาด: {e} กรุณาเข้าสู่ระบบใหม่", "danger")
        return redirect(url_for("login"))


@app.route("/my-table/invite", methods=["POST"])
@login_required
@role_required("customer")
def my_table_invite() -> Any:
    """Host สร้างรหัสเชิญ"""
    try:
        table_id = session.get("table_id")
        try:
            table_id = int(table_id)
        except (ValueError, TypeError):
            flash("ไม่พบโต๊ะของคุณ", "danger")
            return redirect(url_for("my_table"))

        if resto is None:
            flash("ระบบ backend ยังไม่พร้อมใช้งาน", "danger")
            return redirect(url_for("my_table"))

        result: Dict[str, Any] = _safe_result(
            resto.create_invite_code(session.get("username", ""), table_id)
        )

        if result.get("success"):
            code = (result.get("data") or {}).get("invite_code", "")
            flash(f"รหัสเชิญของคุณ: {code} (แชร์ให้เพื่อนได้เลย)", "success")
        else:
            flash(result.get("message", "ไม่สามารถสร้างรหัสเชิญได้"), "danger")

        return redirect(url_for("my_table"))
    except Exception:
        flash("เกิดข้อผิดพลาดในการสร้างรหัสเชิญ", "danger")
        return redirect(url_for("my_table"))


@app.route("/my-table/leave", methods=["POST"])
@login_required
@role_required("customer")
def my_table_leave() -> Any:
    """Member ออกจากโต๊ะ"""
    try:
        table_id = session.get("table_id")
        try:
            table_id = int(table_id)
        except (ValueError, TypeError):
            flash("ไม่พบโต๊ะของคุณ", "danger")
            return redirect(url_for("my_table"))

        if resto is None:
            flash("ระบบ backend ยังไม่พร้อมใช้งาน", "danger")
            return redirect(url_for("my_table"))

        result: Dict[str, Any] = _safe_result(
            resto.leave_table(session.get("username", ""), table_id)
        )

        if result.get("success"):
            session.pop("table_id", None)
            flash(result.get("message", "ออกจากโต๊ะสำเร็จ"), "success")
            return redirect(url_for("select_table", **{"from": "my-table"}))

        flash(result.get("message", "ไม่สามารถออกจากโต๊ะได้"), "danger")
        return redirect(url_for("my_table"))
    except Exception:
        flash("เกิดข้อผิดพลาด", "danger")
        return redirect(url_for("my_table"))


@app.route("/my-table/kick", methods=["POST"])
@login_required
@role_required("customer")
def my_table_kick() -> Any:
    """Host เตะ member"""
    try:
        table_id = session.get("table_id")
        member_username = str(request.form.get("member_username", "")).strip()
        try:
            table_id = int(table_id)
        except (ValueError, TypeError):
            flash("ไม่พบโต๊ะของคุณ", "danger")
            return redirect(url_for("my_table"))

        if resto is None:
            flash("ระบบ backend ยังไม่พร้อมใช้งาน", "danger")
            return redirect(url_for("my_table"))

        result: Dict[str, Any] = _safe_result(
            resto.kick_member(session.get("username", ""), table_id, member_username)
        )

        if result.get("success"):
            flash(result.get("message", "เตะสมาชิกสำเร็จ"), "success")
        else:
            flash(result.get("message", "ไม่สามารถเตะสมาชิกได้"), "danger")

        return redirect(url_for("my_table"))
    except Exception:
        flash("เกิดข้อผิดพลาด", "danger")
        return redirect(url_for("my_table"))


@app.route("/my-table/change", methods=["GET", "POST"])
@login_required
@role_required("customer")
def my_table_change() -> Any:
    """Host ย้ายโต๊ะ"""
    try:
        table_id = session.get("table_id")
        try:
            old_table_id = int(table_id)
        except (ValueError, TypeError):
            flash("ไม่พบโต๊ะของคุณ", "danger")
            return redirect(url_for("my_table"))

        if request.method == "POST":
            new_table_raw: str = str(request.form.get("new_table_id", "")).strip()
            try:
                new_table_id: int = int(new_table_raw)
            except (ValueError, TypeError):
                flash("หมายเลขโต๊ะใหม่ไม่ถูกต้อง", "danger")
                return redirect(url_for("my_table_change"))

            if resto is None:
                flash("ระบบ backend ยังไม่พร้อมใช้งาน", "danger")
                return redirect(url_for("my_table_change"))

            result: Dict[str, Any] = _safe_result(
                resto.change_customer_table(session.get("username", ""), old_table_id, new_table_id)
            )

            if result.get("success"):
                session["table_id"] = new_table_id
                flash(result.get("message", "ย้ายโต๊ะสำเร็จ"), "success")
                return redirect(url_for("my_table"))

            flash(result.get("message", "ไม่สามารถย้ายโต๊ะได้"), "danger")
            return redirect(url_for("my_table_change"))

        # GET: แสดงโต๊ะว่างให้เลือก
        tables_data: List[Dict[str, Any]] = []
        current_table: Optional[Dict[str, Any]] = None

        if db_module is not None:
            loaded = db_module.load_json("tables.json", default=[])
            if isinstance(loaded, list):
                for t in loaded:
                    if not isinstance(t, dict):
                        continue
                    try:
                        tid = int(t.get("id", -1))
                    except (ValueError, TypeError):
                        continue
                    if tid == old_table_id:
                        current_table = t
                    elif str(t.get("status", "")) == "available":
                        tables_data.append(t)

        return render_template(
            "select-table.html",
            tables=tables_data,
            current_table=current_table,
            is_change_mode=True,
            user=_current_user(),
        )

    except Exception:
        flash("เกิดข้อผิดพลาด", "danger")
        return redirect(url_for("my_table"))


@app.route("/my-table/request-bill", methods=["POST"])
@login_required
@role_required("customer")
def my_table_request_bill() -> Any:
    """Host กดขอเช็คบิล"""
    try:
        table_id = session.get("table_id")
        try:
            table_id = int(table_id)
        except (ValueError, TypeError):
            flash("ไม่พบโต๊ะของคุณ", "danger")
            return redirect(url_for("my_table"))

        if resto is None:
            flash("ระบบ backend ยังไม่พร้อมใช้งาน", "danger")
            return redirect(url_for("my_table"))

        result: Dict[str, Any] = _safe_result(
            resto.update_table_status(table_id, "billing", "staff")
        )

        if result.get("success"):
            flash("เรียกพนักงานเก็บเงินเรียบร้อยแล้ว กรุณารอสักครู่", "success")
            try:
                resto.record_log(session.get("username", ""), "customer",
                                 "request_bill", f"ลูกค้าขอเช็คบิลโต๊ะ #{table_id}")
            except Exception:
                pass
        else:
            flash(result.get("message", "ไม่สามารถเรียกเช็คบิลได้"), "danger")

        return redirect(url_for("my_table"))
    except Exception:
        flash("เกิดข้อผิดพลาด", "danger")
        return redirect(url_for("my_table"))


# ===============================================================
# 7) Tables (staff/admin)
# ===============================================================
@app.route("/tables")
@login_required
@role_required("admin", "staff")
def tables() -> Any:
    try:
        tables_data: List[Dict[str, Any]] = []
        if db_module is not None:
            loaded = db_module.load_json("tables.json", default=[])
            if isinstance(loaded, list):
                tables_data = loaded

        summary: Dict[str, int] = {"available": 0, "occupied": 0, "billing": 0}
        for t in tables_data:
            if isinstance(t, dict):
                status: str = str(t.get("status", "available"))
                if status in summary:
                    summary[status] += 1

        return render_template("tables.html", tables=tables_data, summary=summary, user=_current_user())
    except Exception:
        flash("ไม่สามารถโหลดข้อมูลโต๊ะได้", "danger")
        return render_template("tables.html", tables=[], summary={}, user=_current_user())


@app.route("/tables/update-status", methods=["POST"])
@login_required
@role_required("admin", "staff")
def update_table_status_route() -> Any:
    try:
        table_id_raw: str = str(request.form.get("table_id", "")).strip()
        new_status: str = str(request.form.get("status", "")).strip()
        try:
            table_id: int = int(table_id_raw)
        except (ValueError, TypeError):
            flash("หมายเลขโต๊ะไม่ถูกต้อง", "danger")
            return redirect(url_for("tables"))

        if resto is None:
            flash("ระบบ backend ยังไม่พร้อมใช้งาน", "danger")
            return redirect(url_for("tables"))

        result: Dict[str, Any] = _safe_result(
            resto.update_table_status(table_id, new_status, session.get("role", ""))
        )

        if result.get("success"):
            flash(result.get("message", "อัปเดตสถานะโต๊ะสำเร็จ"), "success")
            try:
                resto.record_log(session.get("username", ""), session.get("role", ""),
                                 "update_table_status",
                                 f"เปลี่ยนสถานะโต๊ะ {table_id} เป็น {new_status}")
            except Exception:
                pass
        else:
            flash(result.get("message", "ไม่สามารถเปลี่ยนสถานะโต๊ะได้"), "danger")

        return redirect(url_for("tables"))
    except Exception:
        flash("เกิดข้อผิดพลาดในการเปลี่ยนสถานะโต๊ะ", "danger")
        return redirect(url_for("tables"))


@app.route("/tables/unlock", methods=["POST"])
@login_required
@role_required("admin", "staff")
def tables_unlock() -> Any:
    """Staff ปลดล็อกโต๊ะที่ค้าง (มี option ยกเลิกออเดอร์ + เหตุผล)"""
    try:
        table_id_raw: str = str(request.form.get("table_id", "")).strip()
        try:
            table_id: int = int(table_id_raw)
        except (ValueError, TypeError):
            flash("หมายเลขโต๊ะไม่ถูกต้อง", "danger")
            return redirect(url_for("tables"))

        cancel_orders_raw: str = str(request.form.get("cancel_orders", "0")).strip()
        cancel_orders: bool = (cancel_orders_raw == "1")
        reason: str = str(request.form.get("reason", "")).strip()

        if resto is None:
            flash("ระบบ backend ยังไม่พร้อมใช้งาน", "danger")
            return redirect(url_for("tables"))

        result: Dict[str, Any] = _safe_result(
            resto.unlock_table_by_staff(
                table_id,
                session.get("role", ""),
                cancel_orders=cancel_orders,
                reason=reason,
            )
        )

        if result.get("success"):
            flash(result.get("message", "ปลดล็อกโต๊ะสำเร็จ"), "success")
            try:
                data: Dict[str, Any] = result.get("data", {}) or {}
                cancelled: int = int(data.get("cancelled_count", 0))
                detail: str = f"ปลดล็อกโต๊ะ #{table_id}"
                if cancelled > 0:
                    detail += f" + ยกเลิก {cancelled} ออเดอร์"
                if not cancel_orders:
                    detail += " (คงออเดอร์ไว้)"
                if reason:
                    detail += f" | เหตุผล: {reason}"
                resto.record_log(
                    session.get("username", ""),
                    session.get("role", ""),
                    "unlock_table",
                    detail,
                )
            except Exception:
                pass
        else:
            flash(result.get("message", "ไม่สามารถปลดล็อกได้"), "danger")

        return redirect(url_for("tables"))
    except Exception:
        flash("เกิดข้อผิดพลาดในการปลดล็อกโต๊ะ", "danger")
        return redirect(url_for("tables"))


# ===============================================================
# 8) Menus CRUD
# ===============================================================
@app.route("/menus")
@login_required
@role_required("admin")
def menus_page() -> Any:
    try:
        category: str = str(request.args.get("category", "")).strip()
        search: str = str(request.args.get("search", "")).strip()
        only_available_raw: str = str(request.args.get("only_available", "")).strip()

        menus: List[Dict[str, Any]] = []
        categories: List[str] = []

        if resto is not None:
            result: Dict[str, Any] = _safe_result(
                resto.get_menus(
                    category=category if category else None,
                    search=search if search else None,
                    only_available=(only_available_raw == "1"),
                )
            )
            if result.get("success"):
                menus = result.get("data", []) or []
                categories = result.get("categories", []) or []

        all_menus: List[Dict[str, Any]] = []
        if db_module is not None:
            loaded = db_module.load_json("menus.json", default=[])
            if isinstance(loaded, list):
                all_menus = loaded

        stats: Dict[str, int] = {
            "total": len(all_menus),
            "available": sum(1 for m in all_menus if isinstance(m, dict) and bool(m.get("is_available", False))),
            "unavailable": sum(1 for m in all_menus if isinstance(m, dict) and not bool(m.get("is_available", False))),
        }

        return render_template(
            "menus.html",
            menus=menus, categories=categories,
            current_category=category, search=search,
            only_available=(only_available_raw == "1"),
            stats=stats, user=_current_user(),
        )

    except Exception:
        flash("ไม่สามารถโหลดหน้าจัดการเมนูได้", "danger")
        return redirect(url_for("tables"))


@app.route("/menus/create", methods=["POST"])
@login_required
@role_required("admin")
def menus_create() -> Any:
    try:
        item_data = {
            "name": request.form.get("name", ""),
            "category": request.form.get("category", ""),
            "price": request.form.get("price", "0"),
            "is_available": request.form.get("is_available", "1") == "1",
            "image_url": request.form.get("image_url", ""),
        }
        if resto is None:
            flash("ระบบ backend ยังไม่พร้อมใช้งาน", "danger")
            return redirect(url_for("menus_page"))
        result = _safe_result(resto.crud_menu_item("create", item_data, session.get("role", "")))
        if result.get("success"):
            flash(result.get("message", "เพิ่มเมนูสำเร็จ"), "success")
            try:
                new_item = result.get("data", {}) or {}
                resto.record_log(session.get("username", ""), session.get("role", ""),
                                 "menu_create", f"เพิ่มเมนู '{new_item.get('name', '')}' (id: {new_item.get('id', '')})")
            except Exception:
                pass
        else:
            flash(result.get("message", "ไม่สามารถเพิ่มเมนูได้"), "danger")
        return redirect(url_for("menus_page"))
    except Exception:
        flash("เกิดข้อผิดพลาดในการเพิ่มเมนู", "danger")
        return redirect(url_for("menus_page"))


@app.route("/menus/update", methods=["POST"])
@login_required
@role_required("admin")
def menus_update() -> Any:
    try:
        item_data = {
            "id": request.form.get("id", ""),
            "name": request.form.get("name", ""),
            "category": request.form.get("category", ""),
            "price": request.form.get("price", "0"),
            "is_available": request.form.get("is_available", "1") == "1",
            "image_url": request.form.get("image_url", ""),
        }
        if resto is None:
            flash("ระบบ backend ยังไม่พร้อมใช้งาน", "danger")
            return redirect(url_for("menus_page"))
        result = _safe_result(resto.crud_menu_item("update", item_data, session.get("role", "")))
        if result.get("success"):
            flash(result.get("message", "อัปเดตเมนูสำเร็จ"), "success")
            try:
                resto.record_log(session.get("username", ""), session.get("role", ""),
                                 "menu_update", f"แก้ไขเมนู id '{item_data.get('id', '')}'")
            except Exception:
                pass
        else:
            flash(result.get("message", "ไม่สามารถอัปเดตเมนูได้"), "danger")
        return redirect(url_for("menus_page"))
    except Exception:
        flash("เกิดข้อผิดพลาดในการอัปเดตเมนู", "danger")
        return redirect(url_for("menus_page"))


@app.route("/menus/delete", methods=["POST"])
@login_required
@role_required("admin")
def menus_delete() -> Any:
    try:
        menu_id: str = str(request.form.get("id", "")).strip()
        if not menu_id:
            flash("ไม่พบ id ของเมนูที่ต้องการลบ", "danger")
            return redirect(url_for("menus_page"))
        if resto is None:
            flash("ระบบ backend ยังไม่พร้อมใช้งาน", "danger")
            return redirect(url_for("menus_page"))
        result = _safe_result(resto.crud_menu_item("delete", {"id": menu_id}, session.get("role", "")))
        if result.get("success"):
            flash(result.get("message", "ลบเมนูสำเร็จ"), "success")
            try:
                resto.record_log(session.get("username", ""), session.get("role", ""),
                                 "menu_delete", f"ลบเมนู id '{menu_id}'")
            except Exception:
                pass
        else:
            flash(result.get("message", "ไม่สามารถลบเมนูได้"), "danger")
        return redirect(url_for("menus_page"))
    except Exception:
        flash("เกิดข้อผิดพลาดในการลบเมนู", "danger")
        return redirect(url_for("menus_page"))


@app.route("/menus/toggle", methods=["POST"])
@login_required
@role_required("admin")
def menus_toggle() -> Any:
    try:
        menu_id: str = str(request.form.get("id", "")).strip()
        new_state: str = str(request.form.get("is_available", "1")).strip()
        if not menu_id:
            flash("ไม่พบ id ของเมนู", "danger")
            return redirect(url_for("menus_page"))
        item_data = {"id": menu_id, "is_available": (new_state == "1")}
        if resto is None:
            flash("ระบบ backend ยังไม่พร้อมใช้งาน", "danger")
            return redirect(url_for("menus_page"))
        result = _safe_result(resto.crud_menu_item("update", item_data, session.get("role", "")))
        if result.get("success"):
            status_text: str = "พร้อมขาย" if new_state == "1" else "หมดชั่วคราว"
            flash(f"อัปเดตเมนู '{menu_id}' เป็น '{status_text}' สำเร็จ", "success")
            try:
                resto.record_log(session.get("username", ""), session.get("role", ""),
                                 "menu_toggle", f"สลับสถานะเมนู '{menu_id}' เป็น {status_text}")
            except Exception:
                pass
        else:
            flash(result.get("message", "ไม่สามารถสลับสถานะเมนูได้"), "danger")
        return redirect(url_for("menus_page"))
    except Exception:
        flash("เกิดข้อผิดพลาดในการสลับสถานะเมนู", "danger")
        return redirect(url_for("menus_page"))


# ===============================================================
# 9) POS
# ===============================================================
@app.route("/pos/<int:table_id>")
@login_required
def pos(table_id: int) -> Any:
    try:
        user_role: str = str(session.get("role", ""))

        if user_role == "customer":
            my_table = session.get("table_id")
            try:
                my_table_int = int(my_table)
            except (ValueError, TypeError):
                my_table_int = None

            if my_table_int is None:
                flash("กรุณาเลือกโต๊ะก่อน", "warning")
                return redirect(url_for("select_table", **{"from": "my-table"}))

            if my_table_int != int(table_id):
                flash("คุณไม่มีสิทธิ์เข้าถึงโต๊ะอื่น", "danger")
                return redirect(url_for("pos", table_id=my_table_int))

        category: str = str(request.args.get("category", "")).strip()
        search: str = str(request.args.get("search", "")).strip()

        menus: List[Dict[str, Any]] = []
        categories: List[str] = []
        table_info: Optional[Dict[str, Any]] = None

        if resto is not None:
            result = _safe_result(resto.get_menus(
                category=category if category else None,
                search=search if search else None,
                only_available=False,
            ))
            if result.get("success"):
                menus = result.get("data", []) or []
                categories = result.get("categories", []) or []

        if db_module is not None:
            tables_data = db_module.load_json("tables.json", default=[])
            if isinstance(tables_data, list):
                for t in tables_data:
                    if isinstance(t, dict):
                        try:
                            if int(t.get("id", -1)) == int(table_id):
                                table_info = t
                                break
                        except (ValueError, TypeError):
                            continue

        if table_info is None:
            flash(f"ไม่พบโต๊ะหมายเลข {table_id}", "danger")
            if user_role == "customer":
                return redirect(url_for("my_table"))
            return redirect(url_for("tables"))

        return render_template(
            "pos.html",
            table=table_info, menus=menus, categories=categories,
            current_category=category, search=search,
            user=_current_user(),
        )
    except Exception:
        flash("ไม่สามารถโหลดหน้าสั่งอาหารได้", "danger")
        if session.get("role") == "customer":
            return redirect(url_for("my_table"))
        return redirect(url_for("tables"))


@app.route("/pos/order", methods=["POST"])
@login_required
def pos_order() -> Any:
    try:
        user_role: str = str(session.get("role", ""))

        if user_role == "customer":
            table_id_raw = session.get("table_id")
        else:
            table_id_raw = request.form.get("table_id", "")

        try:
            table_id: int = int(table_id_raw)
        except (ValueError, TypeError):
            flash("หมายเลขโต๊ะไม่ถูกต้อง", "danger")
            return redirect(url_for("tables"))

        note: str = str(request.form.get("note", "")).strip()

        menu_ids: List[str] = request.form.getlist("menu_id[]") or request.form.getlist("menu_id")
        quantities: List[str] = request.form.getlist("quantity[]") or request.form.getlist("quantity")
        item_notes: List[str] = request.form.getlist("item_note[]") or request.form.getlist("item_note")

        # ---------- Validation แต่ละรายการ (แจ้ง error ที่ชัดเจน) ----------
        items: List[Dict[str, Any]] = []
        for idx, menu_id in enumerate(menu_ids):
            menu_id_clean: str = str(menu_id).strip()
            if not menu_id_clean:
                flash("ไม่พบรหัสเมนูในรายการอาหาร กรุณาเลือกใหม่", "danger")
                return redirect(url_for("pos", table_id=table_id))

            qty_raw: str = quantities[idx] if idx < len(quantities) else ""
            try:
                qty: int = int(qty_raw)
            except (ValueError, TypeError):
                flash(f"จำนวนของเมนู '{menu_id_clean}' ต้องเป็นตัวเลขจำนวนเต็ม", "danger")
                return redirect(url_for("pos", table_id=table_id))

            if qty <= 0:
                flash(f"จำนวนของเมนู '{menu_id_clean}' ต้องมากกว่า 0", "danger")
                return redirect(url_for("pos", table_id=table_id))

            if qty > 99:
                flash(f"จำนวนของเมนู '{menu_id_clean}' ต้องไม่เกิน 99 ต่อรายการ", "danger")
                return redirect(url_for("pos", table_id=table_id))

            item_note: str = item_notes[idx].strip() if idx < len(item_notes) else ""

            items.append({
                "menu_id": menu_id_clean,
                "quantity": qty,
                "note": item_note,
            })

        if not items:
            flash("กรุณาเลือกรายการอาหารอย่างน้อย 1 รายการ", "warning")
            return redirect(url_for("pos", table_id=table_id))

        if resto is None:
            flash("ระบบ backend ยังไม่พร้อมใช้งาน", "danger")
            return redirect(url_for("pos", table_id=table_id))

        result = _safe_result(resto.place_order(table_id, items, note=note))

        if result.get("success"):
            order_data = result.get("data", {}) or {}
            flash(f"ส่งออเดอร์ {order_data.get('id', '')} เข้าครัวสำเร็จ", "success")
            try:
                resto.record_log(session.get("username", ""), session.get("role", ""),
                                 "place_order", f"สั่งอาหารโต๊ะ {table_id} จำนวน {len(items)} รายการ")
            except Exception:
                pass
            if user_role == "customer":
                return redirect(url_for("my_table"))
            return redirect(url_for("tables"))

        flash(result.get("message", "ไม่สามารถส่งออเดอร์ได้"), "danger")
        return redirect(url_for("pos", table_id=table_id))

    except Exception:
        flash("เกิดข้อผิดพลาดในการส่งออเดอร์", "danger")
        return redirect(url_for("tables"))


# ===============================================================
# 10) KDS
# ===============================================================
@app.route("/kds")
@login_required
@role_required("admin", "staff")
def kds() -> Any:
    try:
        orders: List[Dict[str, Any]] = []
        if db_module is not None:
            loaded = db_module.load_json("orders.json", default=[])
            if isinstance(loaded, list):
                for o in loaded:
                    if isinstance(o, dict) and str(o.get("status", "")) not in ("served", "cancelled"):
                        orders.append(o)
        try:
            orders.sort(key=lambda x: str(x.get("created_at", "")), reverse=True)
        except Exception:
            pass

        counts: Dict[str, int] = {"pending": 0, "cooking": 0, "served": 0}
        for o in orders:
            status = str(o.get("status", ""))
            if status in counts:
                counts[status] += 1

        return render_template("kds.html", orders=orders, counts=counts, user=_current_user())
    except Exception:
        flash("ไม่สามารถโหลดหน้าจอครัวได้", "danger")
        return render_template("kds.html", orders=[], counts={}, user=_current_user())


@app.route("/kds/update-status", methods=["POST"])
@login_required
@role_required("admin", "staff")
def kds_update_status() -> Any:
    try:
        order_id: str = str(request.form.get("order_id", "")).strip()
        new_status: str = str(request.form.get("status", "")).strip()

        if not order_id:
            flash("ไม่พบรหัสออเดอร์", "danger")
            return redirect(url_for("kds"))
        if new_status not in ("pending", "cooking", "served"):
            flash("สถานะออเดอร์ไม่ถูกต้อง", "danger")
            return redirect(url_for("kds"))
        if db_module is None:
            flash("ระบบ backend ยังไม่พร้อมใช้งาน", "danger")
            return redirect(url_for("kds"))

        orders = db_module.load_json("orders.json", default=[])
        if not isinstance(orders, list):
            flash("ข้อมูลออเดอร์ไม่ถูกต้อง", "danger")
            return redirect(url_for("kds"))

        found = False
        for o in orders:
            if isinstance(o, dict) and str(o.get("id", "")) == order_id:
                o["status"] = new_status
                o["updated_at"] = datetime.now().isoformat(timespec="seconds")
                found = True
                break

        if not found:
            flash(f"ไม่พบออเดอร์ '{order_id}'", "danger")
            return redirect(url_for("kds"))

        if not db_module.save_json("orders.json", orders):
            flash("ไม่สามารถบันทึกข้อมูลออเดอร์ได้", "danger")
            return redirect(url_for("kds"))

        flash(f"อัปเดตออเดอร์ {order_id} เป็น {new_status} สำเร็จ", "success")
        if resto is not None:
            try:
                resto.record_log(session.get("username", ""), session.get("role", ""),
                                 "kds_update_status", f"อัปเดตออเดอร์ {order_id} เป็น {new_status}")
            except Exception:
                pass
        return redirect(url_for("kds"))
    except Exception:
        flash("เกิดข้อผิดพลาดในการอัปเดตสถานะออเดอร์", "danger")
        return redirect(url_for("kds"))


# ===============================================================
# 11) Billing
# ===============================================================
@app.route("/billing/<int:table_id>", methods=["GET", "POST"])
@login_required
@role_required("admin", "staff")
def billing(table_id: int) -> Any:
    try:
        table_info: Optional[Dict[str, Any]] = None

        if db_module is None:
            flash("ระบบ backend ยังไม่พร้อมใช้งาน", "danger")
            return redirect(url_for("tables"))

        tables_data = db_module.load_json("tables.json", default=[])
        if isinstance(tables_data, list):
            for t in tables_data:
                if isinstance(t, dict):
                    try:
                        if int(t.get("id", -1)) == int(table_id):
                            table_info = t
                            break
                    except (ValueError, TypeError):
                        continue

        if table_info is None:
            flash(f"ไม่พบโต๊ะหมายเลข {table_id}", "danger")
            return redirect(url_for("tables"))

        orders = db_module.load_json("orders.json", default=[])
        table_orders: List[Dict[str, Any]] = []
        total_amount: float = 0.0
        if isinstance(orders, list):
            for o in orders:
                if isinstance(o, dict):
                    try:
                        if int(o.get("table_id", -1)) == int(table_id) \
                           and not bool(o.get("paid", False)):
                            table_orders.append(o)
                            total_amount += float(o.get("total_amount", 0) or 0)
                    except (ValueError, TypeError):
                        continue

        combined_order: Optional[Dict[str, Any]] = None
        if table_orders:
            combined_order = {
                "id": ", ".join([str(o.get("id")) for o in table_orders]),
                "items": [item for o in table_orders for item in (o.get("items") or [])],
                "total_amount": round(total_amount, 2),
            }

        if request.method == "POST":
            discount_raw = str(request.form.get("discount_percent", "0")).strip()
            payment_method = str(request.form.get("payment_method", "PromptPay QR")).strip()
            try:
                discount_percent = float(discount_raw) if discount_raw else 0.0
            except (ValueError, TypeError):
                flash("ส่วนลดต้องเป็นตัวเลข", "danger")
                return redirect(url_for("billing", table_id=table_id))

            if resto is None:
                flash("ระบบ backend ยังไม่พร้อมใช้งาน", "danger")
                return redirect(url_for("billing", table_id=table_id))

            result = _safe_result(resto.calculate_and_checkout_bill(
                table_id=table_id, discount_percent=discount_percent,
                payment_method=payment_method,
            ))

            if result.get("success"):
                bill_data = result.get("data", {}) or {}
                flash(f"เช็คบิลสำเร็จ ยอดรวม {bill_data.get('total_amount', 0):,.2f} บาท", "success")
                try:
                    resto.record_log(session.get("username", ""), session.get("role", ""),
                                     "checkout_bill", f"เช็คบิลโต๊ะ {table_id} ยอด {bill_data.get('total_amount', 0)}")
                except Exception:
                    pass
                return redirect(url_for("tables"))

            flash(result.get("message", "ไม่สามารถเช็คบิลได้"), "danger")
            return redirect(url_for("billing", table_id=table_id))

        preview: Dict[str, float] = {
            "subtotal": 0.0, "discount": 0.0, "service_charge": 0.0,
            "vat": 0.0, "total_amount": 0.0,
        }
        if combined_order:
            try:
                subtotal = float(combined_order.get("total_amount", 0.0))
                service_charge = round(subtotal * 0.10, 2)
                vat = round((subtotal + service_charge) * 0.07, 2)
                preview = {
                    "subtotal": round(subtotal, 2),
                    "discount": 0.0,
                    "service_charge": service_charge,
                    "vat": vat,
                    "total_amount": round(subtotal + service_charge + vat, 2),
                }
            except Exception:
                pass

        return render_template(
            "billing.html",
            table=table_info, order=combined_order, preview=preview,
            user=_current_user(),
        )
    except Exception:
        flash("เกิดข้อผิดพลาดในหน้าเช็คบิล", "danger")
        return redirect(url_for("tables"))


# ===============================================================
# 12) Dashboard
# ===============================================================
@app.route("/dashboard")
@login_required
@role_required("admin", "staff")
def dashboard() -> Any:
    try:
        if db_module is None:
            flash("ระบบ backend ยังไม่พร้อมใช้งาน", "danger")
            return redirect(url_for("tables"))

        bills = db_module.load_json("bills.json", default=[])
        orders = db_module.load_json("orders.json", default=[])
        if not isinstance(bills, list): bills = []
        if not isinstance(orders, list): orders = []

        today_str = datetime.now().strftime("%Y-%m-%d")
        total_sales = 0.0
        today_sales = 0.0
        total_bills = len(bills)
        today_bills = 0

        for bill in bills:
            if not isinstance(bill, dict):
                continue
            try:
                amount = float(bill.get("total_amount", 0.0))
            except (ValueError, TypeError):
                amount = 0.0
            total_sales += amount
            paid_at = str(bill.get("paid_at", ""))
            if paid_at.startswith(today_str):
                today_sales += amount
                today_bills += 1

        menu_counter: Dict[str, Dict[str, Any]] = {}
        for order in orders:
            if not isinstance(order, dict):
                continue
            items = order.get("items", [])
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                menu_id = str(item.get("menu_id", ""))
                name = str(item.get("name", ""))
                try:
                    qty = int(item.get("quantity", 0))
                except (ValueError, TypeError):
                    qty = 0
                if not menu_id or qty <= 0:
                    continue
                if menu_id not in menu_counter:
                    menu_counter[menu_id] = {"menu_id": menu_id, "name": name, "qty": 0}
                menu_counter[menu_id]["qty"] += qty

        top_menus = sorted(menu_counter.values(), key=lambda x: x["qty"], reverse=True)[:5]

        stats = {
            "total_sales": round(total_sales, 2),
            "today_sales": round(today_sales, 2),
            "total_bills": total_bills,
            "today_bills": today_bills,
            "top_menus": top_menus,
            "today_date": today_str,
        }
        return render_template("dashboard.html", stats=stats, user=_current_user())
    except Exception:
        flash("ไม่สามารถโหลดข้อมูล Dashboard ได้", "danger")
        return render_template(
            "dashboard.html",
            stats={"total_sales": 0.0, "today_sales": 0.0, "total_bills": 0,
                   "today_bills": 0, "top_menus": [],
                   "today_date": datetime.now().strftime("%Y-%m-%d")},
            user=_current_user(),
        )


# ===============================================================
# 13) Logs
# ===============================================================
@app.route("/logs")
@login_required
@role_required("admin")
def logs() -> Any:
    """แสดง Audit Log ทั้งหมด (เฉพาะ admin) + Pagination"""
    try:
        # ---------- Pagination Params ----------
        page_raw: str = str(request.args.get("page", "1")).strip()
        per_page_raw: str = str(request.args.get("per_page", "10")).strip()

        try:
            page: int = int(page_raw)
        except (ValueError, TypeError):
            page = 1
        if page < 1:
            page = 1

        try:
            per_page: int = int(per_page_raw)
        except (ValueError, TypeError):
            per_page = 10
        if per_page < 5:
            per_page = 5
        if per_page > 50:
            per_page = 50

        # ---------- โหลดข้อมูล ----------
        log_list: List[Dict[str, Any]] = []
        if db_module is not None:
            loaded = db_module.load_json("logs.json", default=[])
            if isinstance(loaded, list):
                log_list = loaded

        # เรียงใหม่สุดขึ้นก่อน
        try:
            log_list = sorted(
                log_list,
                key=lambda x: str(x.get("timestamp", "")) if isinstance(x, dict) else "",
                reverse=True,
            )
        except Exception:
            pass

        # ---------- คำนวณ Pagination ----------
        total: int = len(log_list)
        total_pages: int = (total + per_page - 1) // per_page if total > 0 else 1

        # clamp page ไม่ให้เกิน
        if page > total_pages:
            page = total_pages

        start: int = (page - 1) * per_page
        end: int = start + per_page

        paged_logs: List[Dict[str, Any]] = log_list[start:end]

        pagination: Dict[str, Any] = {
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": total_pages,
            "start": start + 1 if total > 0 else 0,
            "end": min(end, total),
            "has_prev": page > 1,
            "has_next": page < total_pages,
            "prev_page": page - 1 if page > 1 else 1,
            "next_page": page + 1 if page < total_pages else total_pages,
        }

        return render_template(
            "logs.html",
            logs=paged_logs,
            pagination=pagination,
            user=_current_user(),
        )

    except Exception:
        flash("ไม่สามารถโหลด Audit Log ได้", "danger")
        return render_template(
            "logs.html",
            logs=[],
            pagination={
                "page": 1, "per_page": 10, "total": 0, "total_pages": 1,
                "start": 0, "end": 0, "has_prev": False, "has_next": False,
                "prev_page": 1, "next_page": 1,
            },
            user=_current_user(),
        )


# ===============================================================
# 14) Health
# ===============================================================
@app.route("/healthz")
def healthz() -> Any:
    return jsonify({
        "status": "ok",
        "time": datetime.now().isoformat(timespec="seconds"),
        "resto_loaded": resto is not None,
        "db_loaded": db_module is not None,
    }), 200


# ===============================================================
# 15) Error Handlers
# ===============================================================
@app.errorhandler(404)
def not_found_error(error: Any) -> Any:
    try:
        if request.path.startswith("/api/") or request.is_json:
            return jsonify({"success": False, "message": "ไม่พบหน้าที่ต้องการ (404)"}), 404
        return render_template("error.html", error_code=404, error_message="ไม่พบหน้าที่คุณต้องการ"), 404
    except Exception:
        return "404 Not Found", 404


@app.errorhandler(500)
def internal_error(error: Any) -> Any:
    try:
        if request.path.startswith("/api/") or request.is_json:
            return jsonify({"success": False, "message": "เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์ (500)"}), 500
        return render_template("error.html", error_code=500, error_message="เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์"), 500
    except Exception:
        return "500 Internal Server Error", 500


@app.errorhandler(Exception)
def unhandled_exception(error: Any) -> Any:
    try:
        code = getattr(error, "code", 500)
        if not isinstance(code, int) or code < 400 or code > 599:
            code = 500
        if request.path.startswith("/api/") or request.is_json:
            return jsonify({"success": False, "message": f"เกิดข้อผิดพลาด (รหัส {code})"}), code
        return render_template("error.html", error_code=code,
                               error_message="เกิดข้อผิดพลาดในระบบ กรุณาลองใหม่อีกครั้ง"), code
    except Exception:
        return "Internal Server Error", 500


# ===============================================================
# 16) Context Processor
# ===============================================================
@app.context_processor
def inject_user() -> Dict[str, Any]:
    try:
        return {"current_user": _current_user(), "now": datetime.now()}
    except Exception:
        return {"current_user": {"username": "", "role": "", "name": ""}, "now": datetime.now()}


# ===============================================================
# 17) Entry Point
# ===============================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)