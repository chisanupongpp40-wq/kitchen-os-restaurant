"""
modules/restaurant.py
---------------------
โมดูล Business Logic ของระบบร้านอาหาร (Flask)
ครอบคลุมฟังก์ชัน: ล็อกอิน, เมนู, โต๊ะ, ออเดอร์, เช็คบิล, audit log,
ระบบเชิญเพื่อน (invite), ระบบเปลี่ยนโต๊ะ (change table)

ข้อมูลผลลัพธ์ทุกฟังก์ชันจะอยู่ในรูป dict เสมอ:
    {"success": True,  "data": ...}
    {"success": False, "message": "..."}
"""

import secrets
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Set

from werkzeug.security import check_password_hash

try:
    from . import db  # type: ignore
except ImportError:
    import db  # type: ignore


# ---------------------------------------------------------------
# ค่าคงที่ (tuple)
# ---------------------------------------------------------------
ROLES: Tuple[str, ...] = ("admin", "staff", "customer")
ORDER_STATUSES: Tuple[str, ...] = ("pending", "cooking", "served")
TABLE_STATUSES: Tuple[str, ...] = ("available", "occupied", "billing")
PAYMENT_METHODS: Tuple[str, ...] = ("PromptPay QR", "Cash", "Credit Card")

SERVICE_CHARGE_RATE: float = 0.10
VAT_RATE: float = 0.07
INVITE_CODE_LENGTH: int = 6


# ===============================================================
# 1) Authentication
# ===============================================================
def authenticate_user(username: str, password: str) -> Dict[str, Any]:
    """ตรวจสอบการล็อกอิน"""
    try:
        if not isinstance(username, str) or not isinstance(password, str):
            return {"success": False, "message": "ชื่อผู้ใช้และรหัสผ่านต้องเป็นข้อความ"}

        username = username.strip()
        if not username or not password:
            return {"success": False, "message": "กรุณากรอกชื่อผู้ใช้และรหัสผ่าน"}

        users: List[Dict[str, Any]] = db.load_json("users.json", default=[])
        if not isinstance(users, list):
            return {"success": False, "message": "ข้อมูลผู้ใช้ในระบบไม่ถูกต้อง"}

        for user in users:
            if not isinstance(user, dict):
                continue
            if user.get("username") == username:
                hashed_pw: str = str(user.get("password") or user.get("password_hash") or "")
                if not hashed_pw:
                    return {"success": False, "message": "ข้อมูลรหัสผ่านไม่ถูกต้อง"}

                # รองรับทั้ง hashed และ plaintext (ตาม Bypass ที่ยังไม่แก้)
                if check_password_hash(hashed_pw, password) or hashed_pw == password:
                    role: str = str(user.get("role", ""))
                    if role not in ROLES:
                        return {"success": False, "message": "สิทธิ์ผู้ใช้ไม่ถูกต้อง"}
                    return {
                        "success": True,
                        "data": {
                            "username": user.get("username"),
                            "role": role,
                            "name": user.get("name", ""),
                        },
                    }
                else:
                    return {"success": False, "message": "รหัสผ่านไม่ถูกต้อง"}

        return {"success": False, "message": "ไม่พบชื่อผู้ใช้นี้ในระบบ"}

    except Exception as e:
        return {"success": False, "message": f"เกิดข้อผิดพลาดในการล็อกอิน: {e}"}


# ===============================================================
# 2) Register
# ===============================================================
def register_user(username: str, password: str, name: str, role: str = "customer") -> Dict[str, Any]:
    """สมัครสมาชิกใหม่"""
    try:
        username = str(username).strip()
        password = str(password)
        name = str(name).strip()

        if not username or not password or not name:
            return {"success": False, "message": "กรุณากรอกข้อมูลให้ครบทุกช่อง"}

        if len(username) < 3:
            return {"success": False, "message": "ชื่อผู้ใช้ต้องมีความยาวอย่างน้อย 3 ตัวอักษร"}

        if len(password) < 4:
            return {"success": False, "message": "รหัสผ่านต้องมีความยาวอย่างน้อย 4 ตัวอักษร"}

        users: List[Dict[str, Any]] = db.load_json("users.json", default=[])
        if not isinstance(users, list):
            users = []

        for u in users:
            if isinstance(u, dict) and u.get("username") == username:
                return {"success": False, "message": f"ชื่อผู้ใช้ '{username}' มีในระบบแล้ว"}

        from werkzeug.security import generate_password_hash
        new_user = {
            "username": username,
            "password": generate_password_hash(password),
            "role": role if role in ROLES else "customer",
            "name": name,
        }
        users.append(new_user)

        if not db.save_json("users.json", users):
            return {"success": False, "message": "ไม่สามารถบันทึกข้อมูลผู้ใช้ได้"}

        record_log(username, role, "register", f"สมัครสมาชิกใหม่: {name} ({username})")
        return {"success": True, "message": "สมัครสมาชิกสำเร็จ กรุณาเข้าสู่ระบบ"}

    except Exception as e:
        return {"success": False, "message": f"เกิดข้อผิดพลาดในการสมัครสมาชิก: {e}"}


# ===============================================================
# 3) Get Menus
# ===============================================================
def get_menus(
    category: Optional[str] = None,
    search: Optional[str] = None,
    only_available: bool = False,
) -> Dict[str, Any]:
    """ดึงรายการเมนู"""
    try:
        menus: List[Dict[str, Any]] = db.load_json("menus.json", default=[])
        if not isinstance(menus, list):
            return {"success": False, "message": "ข้อมูลเมนูในระบบไม่ถูกต้อง"}

        unique_categories: Set[str] = {
            str(m.get("category", "")).strip()
            for m in menus
            if isinstance(m, dict) and m.get("category")
        }
        unique_categories.discard("")

        filtered: List[Dict[str, Any]] = []
        for menu in menus:
            if not isinstance(menu, dict):
                continue
            if only_available and not bool(menu.get("is_available", False)):
                continue
            if category and str(menu.get("category", "")) != str(category):
                continue
            if search:
                keyword: str = str(search).strip().lower()
                menu_name: str = str(menu.get("name", "")).lower()
                if keyword and keyword not in menu_name:
                    continue
            filtered.append(menu)

        return {
            "success": True,
            "data": filtered,
            "categories": sorted(unique_categories),
            "count": len(filtered),
        }
    except Exception as e:
        return {"success": False, "message": f"เกิดข้อผิดพลาดในการดึงเมนู: {e}"}


# ===============================================================
# 4) CRUD Menu
# ===============================================================
def crud_menu_item(action: str, item_data: Dict[str, Any], user_role: str) -> Dict[str, Any]:
    """เพิ่ม/แก้ไข/ลบเมนู"""
    try:
        if not isinstance(user_role, str) or user_role not in ROLES:
            return {"success": False, "message": "สิทธิ์ผู้ใช้ไม่ถูกต้อง"}

        if user_role != "admin":
            return {"success": False, "message": "เฉพาะ admin เท่านั้นที่จัดการเมนูได้"}

        if not isinstance(item_data, dict):
            return {"success": False, "message": "ข้อมูลเมนูต้องเป็น dict"}

        action = str(action).strip().lower()
        if action not in ("create", "update", "delete"):
            return {"success": False, "message": "action ต้องเป็น create/update/delete"}

        menus: List[Dict[str, Any]] = db.load_json("menus.json", default=[])
        if not isinstance(menus, list):
            return {"success": False, "message": "ข้อมูลเมนูในระบบไม่ถูกต้อง"}

        if action == "create":
            name: str = str(item_data.get("name", "")).strip()
            category: str = str(item_data.get("category", "")).strip()
            if not name:
                return {"success": False, "message": "ชื่อเมนูห้ามว่าง"}
            if not category:
                return {"success": False, "message": "หมวดหมู่ห้ามว่าง"}
            try:
                price: float = float(item_data.get("price", 0))
            except (ValueError, TypeError):
                return {"success": False, "message": "ราคาต้องเป็นตัวเลข"}
            if price <= 0:
                return {"success": False, "message": "ราคาต้องมากกว่า 0"}

            new_id: str = f"M{len(menus) + 1:03d}"
            new_item: Dict[str, Any] = {
                "id": new_id,
                "name": name,
                "category": category,
                "price": round(price, 2),
                "is_available": bool(item_data.get("is_available", True)),
                "image_url": str(item_data.get("image_url", "")).strip(),
            }
            menus.append(new_item)
            if not db.save_json("menus.json", menus):
                return {"success": False, "message": "ไม่สามารถบันทึกข้อมูลเมนูได้"}
            return {"success": True, "message": "เพิ่มเมนูสำเร็จ", "data": new_item}

        elif action == "update":
            menu_id: str = str(item_data.get("id", "")).strip()
            if not menu_id:
                return {"success": False, "message": "ต้องระบุ id ของเมนู"}
            found: bool = False
            for menu in menus:
                if not isinstance(menu, dict) or menu.get("id") != menu_id:
                    continue
                if "name" in item_data:
                    name = str(item_data["name"]).strip()
                    if not name:
                        return {"success": False, "message": "ชื่อเมนูห้ามว่าง"}
                    menu["name"] = name
                if "category" in item_data:
                    category = str(item_data["category"]).strip()
                    if not category:
                        return {"success": False, "message": "หมวดหมู่ห้ามว่าง"}
                    menu["category"] = category
                if "price" in item_data:
                    try:
                        price = float(item_data["price"])
                    except (ValueError, TypeError):
                        return {"success": False, "message": "ราคาต้องเป็นตัวเลข"}
                    if price <= 0:
                        return {"success": False, "message": "ราคาต้องมากกว่า 0"}
                    menu["price"] = round(price, 2)
                if "is_available" in item_data:
                    menu["is_available"] = bool(item_data["is_available"])
                if "image_url" in item_data:
                    menu["image_url"] = str(item_data["image_url"]).strip()
                found = True
                break
            if not found:
                return {"success": False, "message": f"ไม่พบเมนู id '{menu_id}'"}
            if not db.save_json("menus.json", menus):
                return {"success": False, "message": "ไม่สามารถบันทึกข้อมูลเมนูได้"}
            return {"success": True, "message": "อัปเดตเมนูสำเร็จ"}

        else:  # delete
            menu_id = str(item_data.get("id", "")).strip()
            if not menu_id:
                return {"success": False, "message": "ต้องระบุ id ของเมนู"}
            remaining: List[Dict[str, Any]] = [
                m for m in menus
                if isinstance(m, dict) and m.get("id") != menu_id
            ]
            if len(remaining) == len(menus):
                return {"success": False, "message": f"ไม่พบเมนู id '{menu_id}'"}
            if not db.save_json("menus.json", remaining):
                return {"success": False, "message": "ไม่สามารถบันทึกข้อมูลเมนูได้"}
            return {"success": True, "message": "ลบเมนูสำเร็จ"}

    except Exception as e:
        return {"success": False, "message": f"เกิดข้อผิดพลาดในการจัดการเมนู: {e}"}


# ===============================================================
# 5) Update Table Status (staff/admin)
# ===============================================================
def update_table_status(table_id: int, new_status: str, user_role: str) -> Dict[str, Any]:
    """เปลี่ยนสถานะโต๊ะ (เฉพาะ staff/admin)"""
    try:
        if not isinstance(user_role, str) or user_role not in ROLES:
            return {"success": False, "message": "สิทธิ์ผู้ใช้ไม่ถูกต้อง"}
        if user_role == "customer":
            return {"success": False, "message": "ลูกค้าไม่มีสิทธิ์เปลี่ยนสถานะโต๊ะ"}

        try:
            table_id = int(table_id)
        except (ValueError, TypeError):
            return {"success": False, "message": "table_id ต้องเป็นตัวเลขจำนวนเต็ม"}

        new_status = str(new_status).strip()
        if new_status not in TABLE_STATUSES:
            return {"success": False, "message": f"สถานะต้องเป็นหนึ่งใน {TABLE_STATUSES}"}

        tables: List[Dict[str, Any]] = db.load_json("tables.json", default=[])
        if not isinstance(tables, list):
            return {"success": False, "message": "ข้อมูลโต๊ะในระบบไม่ถูกต้อง"}

        idx: int = 0
        found: bool = False
        updated_table: Optional[Dict[str, Any]] = None

        while idx < len(tables):
            table = tables[idx]
            if isinstance(table, dict):
                try:
                    current_id: int = int(table.get("id", -1))
                except (ValueError, TypeError):
                    current_id = -1
                if current_id == table_id:
                    table["status"] = new_status
                    if new_status == "available":
                        table["current_order_id"] = None
                        table["host"] = None
                        table["members"] = []
                        table["invite_code"] = None
                    updated_table = table
                    found = True
                    break
            idx += 1

        if not found or updated_table is None:
            return {"success": False, "message": f"ไม่พบโต๊ะ id {table_id}"}
        if not db.save_json("tables.json", tables):
            return {"success": False, "message": "ไม่สามารถบันทึกข้อมูลโต๊ะได้"}

        return {"success": True, "message": "เปลี่ยนสถานะโต๊ะสำเร็จ", "data": updated_table}

    except Exception as e:
        return {"success": False, "message": f"เกิดข้อผิดพลาดในการเปลี่ยนสถานะโต๊ะ: {e}"}


# ===============================================================
# 6) Place Order
# ===============================================================
def place_order(table_id: int, items: List[Dict[str, Any]], note: str = "") -> Dict[str, Any]:
    """สร้างออเดอร์ใหม่"""
    try:
        try:
            table_id = int(table_id)
        except (ValueError, TypeError):
            return {"success": False, "message": "table_id ต้องเป็นตัวเลขจำนวนเต็ม"}

        if not isinstance(items, list) or len(items) == 0:
            return {"success": False, "message": "ต้องมีรายการอาหารอย่างน้อย 1 รายการ"}

        tables: List[Dict[str, Any]] = db.load_json("tables.json", default=[])
        menus: List[Dict[str, Any]] = db.load_json("menus.json", default=[])
        orders: List[Dict[str, Any]] = db.load_json("orders.json", default=[])

        if not isinstance(tables, list) or not isinstance(menus, list) or not isinstance(orders, list):
            return {"success": False, "message": "ข้อมูลในระบบไม่ถูกต้อง"}

        target_table: Optional[Dict[str, Any]] = None
        for t in tables:
            if isinstance(t, dict):
                try:
                    if int(t.get("id", -1)) == table_id:
                        target_table = t
                        break
                except (ValueError, TypeError):
                    continue
        if target_table is None:
            return {"success": False, "message": f"ไม่พบโต๊ะ id {table_id}"}

        menu_map: Dict[str, Dict[str, Any]] = {
            str(m.get("id")): m for m in menus if isinstance(m, dict)
        }

        order_items: List[Dict[str, Any]] = []
        total_amount: float = 0.0

        for item in items:
            if not isinstance(item, dict):
                continue
            menu_id: str = str(item.get("menu_id", "")).strip()
            if not menu_id:
                return {"success": False, "message": "ต้องระบุ menu_id ในทุกรายการ"}

            try:
                qty: int = int(item.get("quantity", 1))
            except (ValueError, TypeError):
                return {"success": False, "message": "quantity ต้องเป็นจำนวนเต็ม"}
            if qty <= 0:
                return {"success": False, "message": "quantity ต้องมากกว่า 0"}
            if qty > 99:
                return {"success": False, "message": "quantity ต้องไม่เกิน 99 ต่อรายการ"}

            if menu_id not in menu_map:
                return {"success": False, "message": f"ไม่พบเมนู id '{menu_id}'"}

            menu: Dict[str, Any] = menu_map[menu_id]
            if not bool(menu.get("is_available", False)):
                return {"success": False, "message": f"เมนู '{menu.get('name', menu_id)}' หมดชั่วคราว"}

            price: float = float(menu.get("price", 0))
            subtotal: float = round(price * qty, 2)
            total_amount += subtotal

            order_items.append({
                "menu_id": menu_id,
                "name": str(menu.get("name", "")),
                "price": price,
                "quantity": qty,
                "note": str(item.get("note", "")).strip(),
            })

        if not order_items:
            return {"success": False, "message": "ไม่มีรายการอาหารที่ถูกต้อง"}

        order_id: str = f"ORD{len(orders) + 1:03d}"
        new_order: Dict[str, Any] = {
            "id": order_id,
            "table_id": table_id,
            "table_number": int(target_table.get("table_number", table_id)),
            "status": "pending",
            "items": order_items,
            "total_amount": round(total_amount, 2),
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "note": str(note).strip(),
            "ordered_by": str(target_table.get("host", "")),
        }
        orders.append(new_order)

        if not db.save_json("orders.json", orders):
            return {"success": False, "message": "ไม่สามารถบันทึกออเดอร์ได้"}

        target_table["status"] = "occupied"
        target_table["current_order_id"] = order_id
        if not db.save_json("tables.json", tables):
            return {"success": False, "message": "ไม่สามารถอัปเดตสถานะโต๊ะได้"}

        return {"success": True, "message": "ส่งออเดอร์เข้าครัวสำเร็จ", "data": new_order}

    except Exception as e:
        return {"success": False, "message": f"เกิดข้อผิดพลาดในการสั่งอาหาร: {e}"}


# ===============================================================
# 7) Calculate & Checkout Bill
# ===============================================================
def calculate_and_checkout_bill(
    table_id: int,
    discount_percent: float = 0.0,
    payment_method: str = "PromptPay QR",
) -> Dict[str, Any]:
    """คำนวณและเช็คบิล"""
    try:
        try:
            table_id = int(table_id)
            discount_percent = float(discount_percent)
        except (ValueError, TypeError):
            return {"success": False, "message": "ข้อมูลนำเข้าไม่ถูกต้อง"}

        if discount_percent < 0.0 or discount_percent > 100.0:
            return {"success": False, "message": "ส่วนลดต้องอยู่ระหว่าง 0-100"}

        payment_method = str(payment_method).strip()
        if payment_method not in PAYMENT_METHODS:
            return {"success": False, "message": f"วิธีชำระเงินต้องเป็นหนึ่งใน {PAYMENT_METHODS}"}

        tables: List[Dict[str, Any]] = db.load_json("tables.json", default=[])
        orders: List[Dict[str, Any]] = db.load_json("orders.json", default=[])
        bills: List[Dict[str, Any]] = db.load_json("bills.json", default=[])

        if not isinstance(tables, list) or not isinstance(orders, list) or not isinstance(bills, list):
            return {"success": False, "message": "ข้อมูลในระบบไม่ถูกต้อง"}

        target_table: Optional[Dict[str, Any]] = None
        for t in tables:
            if isinstance(t, dict):
                try:
                    if int(t.get("id", -1)) == table_id:
                        target_table = t
                        break
                except (ValueError, TypeError):
                    continue
        if target_table is None:
            return {"success": False, "message": f"ไม่พบโต๊ะ id {table_id}"}

                # รวมออเดอร์ทั้งหมดของโต๊ะที่ยังไม่จ่ายเงิน
        table_orders: List[Dict[str, Any]] = []
        for o in orders:
            if isinstance(o, dict):
                try:
                    if int(o.get("table_id", -1)) == table_id and not bool(o.get("paid", False)):
                        table_orders.append(o)
                except (ValueError, TypeError):
                    continue

        if not table_orders:
            return {"success": False, "message": "โต๊ะนี้ไม่มีออเดอร์ค้างชำระ"}

        subtotal: float = 0.0
        for o in table_orders:
            try:
                subtotal += float(o.get("total_amount", 0.0))
            except (ValueError, TypeError):
                pass

        if subtotal < 0:
            subtotal = 0.0

        discount_amount: float = round(subtotal * (discount_percent / 100.0), 2)
        after_discount: float = subtotal - discount_amount
        service_charge: float = round(after_discount * SERVICE_CHARGE_RATE, 2)
        vat: float = round((after_discount + service_charge) * VAT_RATE, 2)
        total_amount: float = round(after_discount + service_charge + vat, 2)

        bill_id: str = f"BILL{len(bills) + 1:03d}"
        new_bill: Dict[str, Any] = {
            "id": bill_id,
            "table_number": int(target_table.get("table_number", table_id)),
            "subtotal": round(subtotal, 2),
            "discount": discount_amount,
            "service_charge": service_charge,
            "vat": vat,
            "total_amount": total_amount,
            "payment_method": payment_method,
            "paid_at": datetime.now().isoformat(timespec="seconds"),
        }
        bills.append(new_bill)

        if not db.save_json("bills.json", bills):
            return {"success": False, "message": "ไม่สามารถบันทึกใบเสร็จได้"}

                # mark all orders as paid (ไม่เปลี่ยน status — ใช้ flag ใหม่)
        for o in table_orders:
            o["paid"] = True
            o["bill_id"] = bill_id
            o["paid_at"] = datetime.now().isoformat(timespec="seconds")
        db.save_json("orders.json", orders)

        # reset table
        target_table["status"] = "available"
        target_table["current_order_id"] = None
        target_table["host"] = None
        target_table["members"] = []
        target_table["invite_code"] = None
        if not db.save_json("tables.json", tables):
            return {"success": False, "message": "ไม่สามารถอัปเดตสถานะโต๊ะได้"}

        return {"success": True, "message": "เช็คบิลสำเร็จ", "data": new_bill}

    except Exception as e:
        return {"success": False, "message": f"เกิดข้อผิดพลาดในการเช็คบิล: {e}"}


# ===============================================================
# 8) Record Log
# ===============================================================
def record_log(username: str, role: str, action: str, details: str) -> bool:
    """บันทึก Audit Log"""
    try:
        logs: List[Dict[str, Any]] = db.load_json("logs.json", default=[])
        if not isinstance(logs, list):
            logs = []
        log_id: str = f"LOG{len(logs) + 1:03d}"
        logs.append({
            "id": log_id,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "username": str(username),
            "role": str(role),
            "action": str(action),
            "details": str(details),
        })
        return bool(db.save_json("logs.json", logs))
    except Exception:
        return False


# ===============================================================
# 9) 🆕 ระบบจองโต๊ะของลูกค้า (Customer Table System)
# ===============================================================
def assign_table_to_customer(username: str, table_id: int) -> Dict[str, Any]:
    """
    ลูกค้าเลือกโต๊ะครั้งแรก → เป็น host ของโต๊ะ
    ถ้าโต๊ะมี host อยู่แล้ว → ปฏิเสธ
    """
    try:
        username = str(username).strip()
        if not username:
            return {"success": False, "message": "ไม่พบชื่อผู้ใช้"}

        try:
            table_id = int(table_id)
        except (ValueError, TypeError):
            return {"success": False, "message": "table_id ต้องเป็นตัวเลข"}

        tables: List[Dict[str, Any]] = db.load_json("tables.json", default=[])
        if not isinstance(tables, list):
            return {"success": False, "message": "ข้อมูลโต๊ะไม่ถูกต้อง"}

        target: Optional[Dict[str, Any]] = None
        for t in tables:
            if isinstance(t, dict):
                try:
                    if int(t.get("id", -1)) == table_id:
                        target = t
                        break
                except (ValueError, TypeError):
                    continue

        if target is None:
            return {"success": False, "message": f"ไม่พบโต๊ะหมายเลข {table_id}"}

        # ถ้ามี host อยู่แล้ว → ปฏิเสธ
        existing_host: Optional[str] = target.get("host")
        if existing_host:
            if existing_host == username:
                # เป็น host เดิมอยู่แล้ว → ถือว่าเข้าระบบได้เลย
                return {"success": True, "message": "คุณเป็นเจ้าของโต๊ะนี้อยู่แล้ว", "data": target}
            return {"success": False, "message": f"โต๊ะนี้ถูกจองโดย '{existing_host}' แล้ว กรุณาเลือกโต๊ะอื่น"}

        # ต้องเป็นโต๊ะว่าง
        if str(target.get("status", "")) != "available":
            return {"success": False, "message": "โต๊ะนี้ยังไม่ว่าง กรุณาเลือกโต๊ะอื่น"}

        # lock as host
        target["host"] = username
        target["members"] = [username]
        target["invite_code"] = None
        target["status"] = "occupied"

        if not db.save_json("tables.json", tables):
            return {"success": False, "message": "ไม่สามารถบันทึกข้อมูลได้"}

        record_log(username, "customer", "assign_table", f"จองโต๊ะ #{table_id} เป็น host")
        return {"success": True, "message": f"เลือกโต๊ะ #{table_id} สำเร็จ", "data": target}

    except Exception as e:
        return {"success": False, "message": f"เกิดข้อผิดพลาด: {e}"}


def create_invite_code(host_username: str, table_id: int) -> Dict[str, Any]:
    """
    Host สร้าง/ดึงรหัสเชิญของโต๊ะตัวเอง
    """
    try:
        host_username = str(host_username).strip()
        try:
            table_id = int(table_id)
        except (ValueError, TypeError):
            return {"success": False, "message": "table_id ไม่ถูกต้อง"}

        tables: List[Dict[str, Any]] = db.load_json("tables.json", default=[])
        if not isinstance(tables, list):
            return {"success": False, "message": "ข้อมูลโต๊ะไม่ถูกต้อง"}

        target: Optional[Dict[str, Any]] = None
        for t in tables:
            if isinstance(t, dict):
                try:
                    if int(t.get("id", -1)) == table_id:
                        target = t
                        break
                except (ValueError, TypeError):
                    continue

        if target is None:
            return {"success": False, "message": f"ไม่พบโต๊ะ id {table_id}"}

        if target.get("host") != host_username:
            return {"success": False, "message": "เฉพาะเจ้าของโต๊ะเท่านั้นที่สร้างรหัสเชิญได้"}

        # มี code อยู่แล้ว → คืนเลย
        existing_code: Optional[str] = target.get("invite_code")
        if existing_code:
            return {"success": True, "message": "มีรหัสเชิญอยู่แล้ว", "data": {"invite_code": existing_code}}

        # generate new code (unique ไม่ซ้ำกับโต๊ะอื่น)
        existing_codes: Set[str] = {
            str(t.get("invite_code"))
            for t in tables
            if isinstance(t, dict) and t.get("invite_code")
        }

        new_code: str = ""
        for _ in range(20):
            candidate: str = secrets.token_hex(3).upper()[:INVITE_CODE_LENGTH]
            if candidate not in existing_codes:
                new_code = candidate
                break

        if not new_code:
            return {"success": False, "message": "ไม่สามารถสร้างรหัสเชิญได้ กรุณาลองใหม่"}

        target["invite_code"] = new_code
        if not db.save_json("tables.json", tables):
            return {"success": False, "message": "ไม่สามารถบันทึกข้อมูลได้"}

        record_log(host_username, "customer", "create_invite", f"สร้างรหัสเชิญ {new_code} สำหรับโต๊ะ #{table_id}")
        return {"success": True, "message": "สร้างรหัสเชิญสำเร็จ", "data": {"invite_code": new_code}}

    except Exception as e:
        return {"success": False, "message": f"เกิดข้อผิดพลาด: {e}"}


def join_table_with_code(username: str, invite_code: str) -> Dict[str, Any]:
    """
    ลูกค้ากรอกรหัสเชิญเพื่อเข้าร่วมโต๊ะ
    """
    try:
        username = str(username).strip()
        invite_code = str(invite_code).strip().upper()

        if not username or not invite_code:
            return {"success": False, "message": "กรุณากรอกรหัสเชิญ"}

        tables: List[Dict[str, Any]] = db.load_json("tables.json", default=[])
        if not isinstance(tables, list):
            return {"success": False, "message": "ข้อมูลโต๊ะไม่ถูกต้อง"}

        target: Optional[Dict[str, Any]] = None
        for t in tables:
            if isinstance(t, dict) and str(t.get("invite_code", "")).upper() == invite_code:
                target = t
                break

        if target is None:
            return {"success": False, "message": "รหัสเชิญไม่ถูกต้องหรือหมดอายุ"}

        members: List[str] = list(target.get("members") or [])
        if username in members:
            return {"success": True, "message": "คุณอยู่ในโต๊ะนี้อยู่แล้ว", "data": target}

        if str(target.get("status", "")) == "billing":
            return {"success": False, "message": "โต๊ะนี้กำลังปิดบิล ไม่สามารถเข้าร่วมได้"}

        members.append(username)
        target["members"] = members
        # ถ้ามีการ join → ล้าง code เก่าเพื่อไม่ให้คนอื่นใช้ซ้ำ (optional: comment นี้ถ้าไม่อยาก)
        # target["invite_code"] = None

        if not db.save_json("tables.json", tables):
            return {"success": False, "message": "ไม่สามารถบันทึกข้อมูลได้"}

        host_name: str = str(target.get("host", ""))
        record_log(username, "customer", "join_table", f"เข้าร่วมโต๊ะ #{target.get('table_number')} (host: {host_name})")
        return {"success": True, "message": f"เข้าร่วมโต๊ะ #{target.get('table_number')} สำเร็จ", "data": target}

    except Exception as e:
        return {"success": False, "message": f"เกิดข้อผิดพลาด: {e}"}


def get_my_table_info(username: str) -> Dict[str, Any]:
    """
    ดึงข้อมูลโต๊ะที่ user สังกัดอยู่ (ทั้ง host และ member)
    """
    try:
        username = str(username).strip()
        if not username:
            return {"success": False, "message": "ไม่พบชื่อผู้ใช้"}

        tables: List[Dict[str, Any]] = db.load_json("tables.json", default=[])
        if not isinstance(tables, list):
            return {"success": False, "message": "ข้อมูลโต๊ะไม่ถูกต้อง"}

        for t in tables:
            if not isinstance(t, dict):
                continue
            members: List[str] = list(t.get("members") or [])
            if username in members:
                # ดึงออเดอร์ของโต๊ะนี้ที่ยัง active
                orders: List[Dict[str, Any]] = db.load_json("orders.json", default=[])
                active_orders: List[Dict[str, Any]] = []
                total: float = 0.0
                if isinstance(orders, list):
                    for o in orders:
                        if not isinstance(o, dict):
                            continue
                        try:
                            if int(o.get("table_id", -1)) == int(t.get("id", -1)) \
                               and not bool(o.get("paid", False)):
                                active_orders.append(o)
                                total += float(o.get("total_amount", 0) or 0)
                        except (ValueError, TypeError):
                            continue

                is_host: bool = (t.get("host") == username)
                return {
                    "success": True,
                    "data": {
                        "table": t,
                        "is_host": is_host,
                        "orders": active_orders,
                        "subtotal": round(total, 2),
                    },
                }

        return {"success": False, "message": "คุณยังไม่ได้เลือกโต๊ะ"}

    except Exception as e:
        return {"success": False, "message": f"เกิดข้อผิดพลาด: {e}"}


def leave_table(username: str, table_id: int) -> Dict[str, Any]:
    """
    Member ออกจากโต๊ะ (host ห้ามใช้ — ต้องใช้ change หรือ checkout แทน)
    """
    try:
        username = str(username).strip()
        try:
            table_id = int(table_id)
        except (ValueError, TypeError):
            return {"success": False, "message": "table_id ไม่ถูกต้อง"}

        tables: List[Dict[str, Any]] = db.load_json("tables.json", default=[])
        if not isinstance(tables, list):
            return {"success": False, "message": "ข้อมูลโต๊ะไม่ถูกต้อง"}

        target: Optional[Dict[str, Any]] = None
        for t in tables:
            if isinstance(t, dict):
                try:
                    if int(t.get("id", -1)) == table_id:
                        target = t
                        break
                except (ValueError, TypeError):
                    continue

        if target is None:
            return {"success": False, "message": f"ไม่พบโต๊ะ id {table_id}"}

        if target.get("host") == username:
            return {"success": False, "message": "เจ้าของโต๊ะออกไม่ได้ กรุณาใช้ 'เปลี่ยนโต๊ะ' แทน"}

        members: List[str] = list(target.get("members") or [])
        if username not in members:
            return {"success": False, "message": "คุณไม่ได้อยู่ในโต๊ะนี้"}

        members.remove(username)
        target["members"] = members

        if not db.save_json("tables.json", tables):
            return {"success": False, "message": "ไม่สามารถบันทึกข้อมูลได้"}

        record_log(username, "customer", "leave_table", f"ออกจากโต๊ะ #{target.get('table_number')}")
        return {"success": True, "message": "ออกจากโต๊ะสำเร็จ"}

    except Exception as e:
        return {"success": False, "message": f"เกิดข้อผิดพลาด: {e}"}


def kick_member(host_username: str, table_id: int, member_username: str) -> Dict[str, Any]:
    """
    Host เตะ member ออกจากโต๊ะ
    """
    try:
        host_username = str(host_username).strip()
        member_username = str(member_username).strip()
        try:
            table_id = int(table_id)
        except (ValueError, TypeError):
            return {"success": False, "message": "table_id ไม่ถูกต้อง"}

        if not member_username:
            return {"success": False, "message": "ไม่พบชื่อสมาชิกที่ต้องการเตะ"}

        tables: List[Dict[str, Any]] = db.load_json("tables.json", default=[])
        if not isinstance(tables, list):
            return {"success": False, "message": "ข้อมูลโต๊ะไม่ถูกต้อง"}

        target: Optional[Dict[str, Any]] = None
        for t in tables:
            if isinstance(t, dict):
                try:
                    if int(t.get("id", -1)) == table_id:
                        target = t
                        break
                except (ValueError, TypeError):
                    continue

        if target is None:
            return {"success": False, "message": f"ไม่พบโต๊ะ id {table_id}"}

        if target.get("host") != host_username:
            return {"success": False, "message": "เฉพาะเจ้าของโต๊ะเท่านั้นที่เตะสมาชิกได้"}

        if member_username == host_username:
            return {"success": False, "message": "เจ้าของโต๊ะเตะตัวเองไม่ได้"}

        members: List[str] = list(target.get("members") or [])
        if member_username not in members:
            return {"success": False, "message": "ไม่พบสมาชิกคนนี้ในโต๊ะ"}

        members.remove(member_username)
        target["members"] = members

        if not db.save_json("tables.json", tables):
            return {"success": False, "message": "ไม่สามารถบันทึกข้อมูลได้"}

        record_log(host_username, "customer", "kick_member", f"เตะ {member_username} ออกจากโต๊ะ #{target.get('table_number')}")
        return {"success": True, "message": f"เตะ {member_username} สำเร็จ"}

    except Exception as e:
        return {"success": False, "message": f"เกิดข้อผิดพลาด: {e}"}


def change_customer_table(username: str, old_table_id: int, new_table_id: int) -> Dict[str, Any]:
    """
    Host ย้ายทั้งกลุ่มไปโต๊ะใหม่ พร้อมออเดอร์ที่ยัง active
    """
    try:
        username = str(username).strip()
        try:
            old_table_id = int(old_table_id)
            new_table_id = int(new_table_id)
        except (ValueError, TypeError):
            return {"success": False, "message": "table_id ไม่ถูกต้อง"}

        if old_table_id == new_table_id:
            return {"success": False, "message": "โต๊ะใหม่ต้องไม่ใช่โต๊ะเดิม"}

        tables: List[Dict[str, Any]] = db.load_json("tables.json", default=[])
        if not isinstance(tables, list):
            return {"success": False, "message": "ข้อมูลโต๊ะไม่ถูกต้อง"}

        old_table: Optional[Dict[str, Any]] = None
        new_table: Optional[Dict[str, Any]] = None
        for t in tables:
            if isinstance(t, dict):
                try:
                    tid = int(t.get("id", -1))
                    if tid == old_table_id:
                        old_table = t
                    elif tid == new_table_id:
                        new_table = t
                except (ValueError, TypeError):
                    continue

        if old_table is None:
            return {"success": False, "message": f"ไม่พบโต๊ะ id {old_table_id}"}
        if new_table is None:
            return {"success": False, "message": f"ไม่พบโต๊ะ id {new_table_id}"}

        if old_table.get("host") != username:
            return {"success": False, "message": "เฉพาะเจ้าของโต๊ะเท่านั้นที่ย้ายโต๊ะได้"}

        if str(new_table.get("status", "")) != "available":
            return {"success": False, "message": f"โต๊ะ #{new_table_id} ไม่ว่าง กรุณาเลือกโต๊ะอื่น"}

        # ย้าย members
        members: List[str] = list(old_table.get("members") or [])
        new_table["host"] = username
        new_table["members"] = members
        new_table["invite_code"] = old_table.get("invite_code")
        new_table["status"] = "occupied"

        # ย้ายออเดอร์ที่ยัง active (pending + cooking)
        orders: List[Dict[str, Any]] = db.load_json("orders.json", default=[])
        if isinstance(orders, list):
            for o in orders:
                if not isinstance(o, dict):
                    continue
                try:
                    if int(o.get("table_id", -1)) == old_table_id \
                       and str(o.get("status", "")) in ("pending", "cooking"):
                        o["table_id"] = new_table_id
                        o["table_number"] = int(new_table.get("table_number", new_table_id))
                except (ValueError, TypeError):
                    continue
            db.save_json("orders.json", orders)

        # หา current_order_id ใหม่ (ออเดอร์ล่าสุดที่ยัง active)
        latest_order_id: Optional[str] = None
        if isinstance(orders, list):
            for o in orders:
                if isinstance(o, dict):
                    try:
                        if int(o.get("table_id", -1)) == new_table_id \
                           and str(o.get("status", "")) != "served":
                            latest_order_id = str(o.get("id", ""))
                    except (ValueError, TypeError):
                        continue

        new_table["current_order_id"] = latest_order_id

        # เคลียร์โต๊ะเก่า
        old_table["status"] = "available"
        old_table["current_order_id"] = None
        old_table["host"] = None
        old_table["members"] = []
        old_table["invite_code"] = None

        if not db.save_json("tables.json", tables):
            return {"success": False, "message": "ไม่สามารถบันทึกข้อมูลได้"}

        record_log(username, "customer", "change_table",
                   f"ย้ายจากโต๊ะ #{old_table_id} ไป #{new_table_id} ({len(members)} คน)")

        return {
            "success": True,
            "message": f"ย้ายไปโต๊ะ #{new_table_id} สำเร็จ",
            "data": new_table,
        }

    except Exception as e:
        return {"success": False, "message": f"เกิดข้อผิดพลาด: {e}"}


def unlock_table_by_staff(
    table_id: int,
    user_role: str,
    cancel_orders: bool = True,
    reason: str = "",
) -> Dict[str, Any]:
    """
    Staff/Admin ปลดล็อกโต๊ะที่ค้าง

    Args:
        table_id: ID ของโต๊ะ
        user_role: admin หรือ staff
        cancel_orders: ถ้า True → mark ออเดอร์ pending/cooking เป็น cancelled
        reason: เหตุผลในการปลดล็อก (optional)

    Returns:
        dict: {"success": True, "data": {"table": ..., "cancelled_count": int}}
    """
    try:
        if user_role not in ("admin", "staff"):
            return {"success": False, "message": "เฉพาะ staff/admin เท่านั้นที่ปลดล็อกได้"}

        try:
            table_id = int(table_id)
        except (ValueError, TypeError):
            return {"success": False, "message": "table_id ไม่ถูกต้อง"}

        reason = str(reason).strip()[:200]  # จำกัด 200 ตัวอักษร

        tables: List[Dict[str, Any]] = db.load_json("tables.json", default=[])
        if not isinstance(tables, list):
            return {"success": False, "message": "ข้อมูลโต๊ะไม่ถูกต้อง"}

        target: Optional[Dict[str, Any]] = None
        for t in tables:
            if isinstance(t, dict):
                try:
                    if int(t.get("id", -1)) == table_id:
                        target = t
                        break
                except (ValueError, TypeError):
                    continue

        if target is None:
            return {"success": False, "message": f"ไม่พบโต๊ะ id {table_id}"}

        # ---------- Cancelled Orders (ถ้าเลือก) ----------
        cancelled_count: int = 0
        if cancel_orders:
            orders: List[Dict[str, Any]] = db.load_json("orders.json", default=[])
            if isinstance(orders, list):
                now_iso: str = datetime.now().isoformat(timespec="seconds")
                for o in orders:
                    if not isinstance(o, dict):
                        continue
                    try:
                        if int(o.get("table_id", -1)) == table_id \
                           and str(o.get("status", "")) in ("pending", "cooking"):
                            o["status"] = "cancelled"
                            o["cancelled_at"] = now_iso
                            o["cancel_reason"] = reason or "ปลดล็อกโต๊ะโดย staff"
                            cancelled_count += 1
                    except (ValueError, TypeError):
                        continue
                db.save_json("orders.json", orders)

        # ---------- Reset Table ----------
        target["status"] = "available"
        target["current_order_id"] = None
        target["host"] = None
        target["members"] = []
        target["invite_code"] = None

        if not db.save_json("tables.json", tables):
            return {"success": False, "message": "ไม่สามารถบันทึกข้อมูลได้"}

        # ---------- สร้างข้อความ success ----------
        msg: str = f"ปลดล็อกโต๊ะ #{table_id} สำเร็จ"
        if cancel_orders and cancelled_count > 0:
            msg += f" (ยกเลิก {cancelled_count} ออเดอร์)"
        elif not cancel_orders:
            msg += " (ออเดอร์ยังค้างใน KDS)"

        return {
            "success": True,
            "message": msg,
            "data": {
                "table": target,
                "cancelled_count": cancelled_count,
            },
        }

    except Exception as e:
        return {"success": False, "message": f"เกิดข้อผิดพลาด: {e}"}