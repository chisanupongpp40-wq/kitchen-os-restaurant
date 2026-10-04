import json
import os
import random
from datetime import datetime
from werkzeug.security import generate_password_hash

DATA_DIR = "data"

def write_json(filename, data):
    filepath = os.path.join(DATA_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[OK] สร้างไฟล์ {filepath} เรียบร้อย")

def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    now_iso = datetime.now().isoformat(timespec="seconds")

    # 1. users.json
    users = [
        {"username": "admin", "password": generate_password_hash("admin123"), "role": "admin", "name": "ผู้จัดการร้าน"},
        {"username": "staff", "password": generate_password_hash("staff123"), "role": "staff", "name": "พนักงานบริการ"},
        {"username": "customer", "password": generate_password_hash("customer123"), "role": "customer", "name": "ลูกค้าทั่วไป"},
    ]
    write_json("users.json", users)

    # 2. tables.json (พร้อม field ใหม่: host, members, invite_code)
    tables = []
    for i in range(1, 9):
        tables.append({
            "id": i,
            "table_number": i,
            "seats": [2, 4, 6, 8][(i - 1) % 4],
            "status": "available",
            "current_order_id": None,
            "host": None,
            "members": [],
            "invite_code": None,
        })
    write_json("tables.json", tables)

    # 3. menus.json
    menus = [
        {"id": "M001", "name": "ข้าวผัดกุ้ง", "category": "จานหลัก", "price": 120.0, "is_available": True,
         "image_url": "https://images.unsplash.com/photo-1512058564366-18510be2db19?auto=format&fit=crop&w=400&q=80"},
        {"id": "M002", "name": "ต้มยำกุ้ง", "category": "จานหลัก", "price": 180.0, "is_available": True,
         "image_url": "https://images.unsplash.com/photo-1548943487-a2e4e43b4853?auto=format&fit=crop&w=400&q=80"},
        {"id": "M003", "name": "ผัดไทย", "category": "จานหลัก", "price": 100.0, "is_available": True,
         "image_url": "https://images.unsplash.com/photo-1559314809-0d155014e29e?auto=format&fit=crop&w=400&q=80"},
        {"id": "M004", "name": "ปีกไก่ทอด", "category": "ทานเล่น", "price": 90.0, "is_available": True,
         "image_url": "https://images.unsplash.com/photo-1527477396000-e27163b481c2?auto=format&fit=crop&w=400&q=80"},
        {"id": "M005", "name": "ปอเปี๊ยะทอด", "category": "ทานเล่น", "price": 80.0, "is_available": True,
         "image_url": "https://images.unsplash.com/photo-1544025162-d76694265947?auto=format&fit=crop&w=400&q=80"},
        {"id": "M006", "name": "สลัดผลไม้", "category": "ทานเล่น", "price": 110.0, "is_available": False,
         "image_url": "https://images.unsplash.com/photo-1546069901-ba9599a7e63c?auto=format&fit=crop&w=400&q=80"},
        {"id": "M007", "name": "น้ำมะนาว", "category": "เครื่องดื่ม", "price": 45.0, "is_available": True,
         "image_url": "https://images.unsplash.com/photo-1497534446932-c925b458314e?auto=format&fit=crop&w=400&q=80"},
        {"id": "M008", "name": "ชาไทย", "category": "เครื่องดื่ม", "price": 50.0, "is_available": True,
         "image_url": "https://images.unsplash.com/photo-1544145945-f90425340c7e?auto=format&fit=crop&w=400&q=80"},
        {"id": "M009", "name": "ข้าวเหนียวมะม่วง", "category": "ของหวาน", "price": 120.0, "is_available": True,
         "image_url": "https://images.unsplash.com/photo-1551024506-0bccd828d307?auto=format&fit=crop&w=400&q=80"},
        {"id": "M010", "name": "ไอศกรีมกะทิ", "category": "ของหวาน", "price": 60.0, "is_available": True,
         "image_url": "https://images.unsplash.com/photo-1563805042-7684c019e1cb?auto=format&fit=crop&w=400&q=80"},
    ]
    write_json("menus.json", menus)

    # 4. orders.json (ว่างเปล่า — ให้ระบบสร้างใหม่)
    write_json("orders.json", [])

    # 5. bills.json (ว่างเปล่า)
    write_json("bills.json", [])

    # 6. logs.json (เริ่มต้น)
    logs = [
        {"id": "LOG001", "timestamp": now_iso, "username": "admin", "role": "admin",
         "action": "seed_data", "details": "สร้างข้อมูลจำลองเริ่มต้น"},
    ]
    write_json("logs.json", logs)

if __name__ == "__main__":
    try:
        main()
        print("\n[DONE] สร้างข้อมูลจำลองครบทั้ง 6 ไฟล์สำเร็จในโฟลเดอร์ data/")
    except Exception as e:
        print(f"[ERROR] เกิดข้อผิดพลาด: {e}")