"""
modules/db.py
-------------
โมดูลจัดการการอ่าน/เขียนไฟล์ JSON สำหรับโปรเจกต์ร้านอาหาร (Flask)
ทุกฟังก์ชันถูกครอบ try...except เพื่อไม่ให้เกิด Unhandled Exception

SECURITY:
- ป้องกัน Path Traversal (ห้าม .., /, \\)
- Atomic write

DEPLOYMENT:
- Local: เขียนที่ data/
- Vercel: เขียนที่ /tmp/kitchen_os_data (เพราะ Vercel read-only)
"""

import json
import os
import re
import shutil
from typing import Any, Optional

# ---------------------------------------------------------------
# Path
# ---------------------------------------------------------------
_THIS_DIR: str = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT: str = os.path.dirname(_THIS_DIR)
_ORIGINAL_DATA_DIR: str = os.path.join(_PROJECT_ROOT, "data")

_ALLOWED_FILENAME_PATTERN = re.compile(r"^[A-Za-z0-9_\-]+\.json$")


def _setup_data_dir() -> str:
    """
    จัดการ DATA_DIR ให้เขียนได้ทั้ง local และ Vercel
    - Local: ใช้ data/ ปกติ
    - Vercel: ใช้ /tmp/kitchen_os_data + copy seed data ไป /tmp ครั้งแรก
    """
    is_vercel: bool = (
        os.environ.get("VERCEL") == "1"
        or os.environ.get("VERCEL_ENV") is not None
        or os.environ.get("NOW_REGION") is not None
    )

    if not is_vercel:
        return _ORIGINAL_DATA_DIR

    tmp_data_dir: str = "/tmp/kitchen_os_data"
    try:
        if not os.path.exists(tmp_data_dir):
            os.makedirs(tmp_data_dir, exist_ok=True)

            if os.path.exists(_ORIGINAL_DATA_DIR):
                for filename in os.listdir(_ORIGINAL_DATA_DIR):
                    if filename.endswith(".json"):
                        src: str = os.path.join(_ORIGINAL_DATA_DIR, filename)
                        dst: str = os.path.join(tmp_data_dir, filename)
                        try:
                            shutil.copy(src, dst)
                        except Exception:
                            pass
        return tmp_data_dir
    except Exception:
        return _ORIGINAL_DATA_DIR


DATA_DIR: str = _setup_data_dir()


def _is_safe_filename(filename: str) -> bool:
    """ตรวจสอบชื่อไฟล์ว่าปลอดภัยหรือไม่"""
    try:
        if not isinstance(filename, str):
            return False
        name = filename.strip()
        if not name:
            return False
        if ".." in name or "/" in name or "\\" in name:
            return False
        if name.startswith("/") or name.startswith("\\"):
            return False
        if len(name) >= 2 and name[1] == ":":
            return False
        if "\x00" in name:
            return False
        if not _ALLOWED_FILENAME_PATTERN.match(name):
            return False
        return True
    except Exception:
        return False


def _get_safe_filepath(filename: str) -> Optional[str]:
    """คืน filepath ที่ปลอดภัย หรือ None ถ้าไม่ผ่าน"""
    try:
        if not _is_safe_filename(filename):
            return None
        filepath = os.path.abspath(os.path.join(DATA_DIR, filename))
        data_dir_abs = os.path.abspath(DATA_DIR)
        try:
            common = os.path.commonpath([filepath, data_dir_abs])
        except ValueError:
            return None
        if common != data_dir_abs:
            return None
        return filepath
    except Exception:
        return None


def load_json(filename: str, default: Optional[Any] = None) -> Any:
    """โหลดข้อมูลจากไฟล์ data/{filename}"""
    if default is None:
        default = []

    try:
        filepath = _get_safe_filepath(filename)
        if filepath is None:
            return default
        if not os.path.exists(filepath):
            return default

        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(default, list) and not isinstance(data, list):
            return default
        if isinstance(default, dict) and not isinstance(data, dict):
            return default
        return data
    except Exception:
        return default


def save_json(filename: str, data: Any) -> bool:
    """บันทึกข้อมูลลงไฟล์ data/{filename} แบบ atomic write"""
    try:
        filepath = _get_safe_filepath(filename)
        if filepath is None:
            return False

        os.makedirs(DATA_DIR, exist_ok=True)
        tmp_path: str = filepath + ".tmp"

        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        os.replace(tmp_path, filepath)
        return True
    except Exception:
        try:
            if "tmp_path" in locals() and os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        return False