"""
modules/db.py
-------------
โมดูลจัดการการอ่าน/เขียนไฟล์ JSON สำหรับโปรเจกต์ร้านอาหาร (Flask)
ทุกฟังก์ชันถูกครอบ try...except เพื่อไม่ให้เกิด Unhandled Exception

SECURITY:
- ป้องกัน Path Traversal (ห้ามใช้ .., /, \, absolute path)
- Atomic write (เขียนไฟล์ชั่วคราวก่อน rename ทับ)
- จำกัดเฉพาะ .json ที่อยู่ใต้ data/ เท่านั้น
"""

import json
import os
import re
from typing import Any, Optional

# ---------------------------------------------------------------
# Path ของโฟลเดอร์ data/
# ---------------------------------------------------------------
_THIS_DIR: str = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT: str = os.path.dirname(_THIS_DIR)
DATA_DIR: str = os.path.join(_PROJECT_ROOT, "data")

# ชื่อไฟล์ที่อนุญาต: ตัวอักษร ตัวเลข _ - . เท่านั้น + ต้องลงท้าย .json
_ALLOWED_FILENAME_PATTERN = re.compile(r"^[A-Za-z0-9_\-]+\.json$")


def _is_safe_filename(filename: str) -> bool:
    """
    ตรวจสอบชื่อไฟล์ว่าปลอดภัยหรือไม่
    - ต้องเป็น string ที่ไม่ว่าง
    - ต้องไม่มี .. / \\ (path traversal)
    - ต้องไม่มี absolute path (ขึ้นต้นด้วย / หรือ drive letter)
    - ต้องตรงกับ pattern: [A-Za-z0-9_-]+.json
    """
    try:
        if not isinstance(filename, str):
            return False

        name = filename.strip()
        if not name:
            return False

        # ปฏิเสธ path traversal patterns
        if ".." in name or "/" in name or "\\" in name:
            return False

        # ปฏิเสธ absolute path (Windows drive หรือ Unix absolute)
        if name.startswith("/") or name.startswith("\\"):
            return False
        if len(name) >= 2 and name[1] == ":":
            return False

        # ปฏิเสธ null byte
        if "\x00" in name:
            return False

        # ต้องตรง pattern .json ที่อนุญาต
        if not _ALLOWED_FILENAME_PATTERN.match(name):
            return False

        return True

    except Exception:
        return False


def _get_safe_filepath(filename: str) -> Optional[str]:
    """
    คืน filepath เต็มที่ปลอดภัย หรือ None ถ้าไม่ผ่าน validation
    ตรวจสอบเพิ่มเติมว่า path ที่ได้ต้องอยู่ใต้ DATA_DIR จริง
    """
    try:
        if not _is_safe_filename(filename):
            return None

        filepath = os.path.abspath(os.path.join(DATA_DIR, filename))
        data_dir_abs = os.path.abspath(DATA_DIR)

        # path ต้องอยู่ใต้ DATA_DIR (ใช้ commonpath ป้องกัน symlink games)
        try:
            common = os.path.commonpath([filepath, data_dir_abs])
        except ValueError:
            # ต่าง drive / invalid path
            return None

        if common != data_dir_abs:
            return None

        return filepath

    except Exception:
        return None


def load_json(filename: str, default: Optional[Any] = None) -> Any:
    """
    โหลดข้อมูลจากไฟล์ data/{filename}

    Args:
        filename: ชื่อไฟล์ เช่น "users.json" (ห้ามมี path)
        default: ค่าที่จะคืนกลับหากโหลดไม่สำเร็จ (ถ้าไม่ระบุจะใช้ [])

    Returns:
        Any: ข้อมูลที่โหลดได้ หรือค่า default ถ้าเกิดข้อผิดพลาด
    """
    if default is None:
        default = []

    try:
        filepath = _get_safe_filepath(filename)
        if filepath is None:
            # filename ไม่ปลอดภัย → ปฏิเสธ
            return default

        if not os.path.exists(filepath):
            return default

        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        # คืนค่าตามชนิดของ default ที่ผู้ใช้ต้องการ
        if isinstance(default, list) and not isinstance(data, list):
            return default
        if isinstance(default, dict) and not isinstance(data, dict):
            return default

        return data

    except Exception:
        return default


def save_json(filename: str, data: Any) -> bool:
    """
    บันทึกข้อมูลลงไฟล์ data/{filename} แบบ atomic write
    (เขียนไฟล์ชั่วคราวก่อนแล้วค่อย rename ทับ เพื่อป้องกันไฟล์เสียหาย)

    Args:
        filename: ชื่อไฟล์ปลายทาง (ห้ามมี path)
        data: ข้อมูลที่ต้องการบันทึก (ต้อง JSON serializable)

    Returns:
        bool: True ถ้าบันทึกสำเร็จ, False ถ้าไม่สำเร็จ
    """
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
        # พยายามลบไฟล์ชั่วคราวทิ้ง
        try:
            if "tmp_path" in locals() and os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        return False