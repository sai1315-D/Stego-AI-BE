import uuid
import json
import os
from datetime import datetime
from supabase import create_client, Client
from app.core.config import settings

class MockResponse:
    def __init__(self, data):
        self.data = data

class MockQueryBuilder:
    def __init__(self, table_name, db):
        self.table_name = table_name
        self.db = db
        self.filters = []
        self.order_by = None
        self.order_desc = False
        self.limit_val = None
        self.op = "select"
        self.insert_record = None
        self.update_values = None

    def select(self, columns="*"):
        self.op = "select"
        return self

    def eq(self, column, value):
        self.filters.append((column, value))
        return self

    def order(self, column, desc=False):
        self.order_by = column
        self.order_desc = desc
        return self

    def limit(self, val):
        self.limit_val = val
        return self

    def insert(self, record):
        self.op = "insert"
        self.insert_record = record
        return self

    def update(self, values):
        self.op = "update"
        self.update_values = values
        return self

    def delete(self):
        self.op = "delete"
        return self

    def execute(self):
        if self.op == "insert":
            inserted = self.db.insert_row(self.table_name, self.insert_record)
            return MockResponse([inserted])

        items = self.db.get_table(self.table_name)
        
        filtered_items = []
        remaining_items = []
        for item in items:
            match = True
            for col, val in self.filters:
                if item.get(col) != val:
                    match = False
                    break
            if match:
                filtered_items.append(item)
            else:
                remaining_items.append(item)

        if self.op == "select":
            result_items = [item.copy() for item in filtered_items]
            if self.order_by:
                result_items.sort(
                    key=lambda x: x.get(self.order_by) or "",
                    reverse=self.order_desc
                )
            if self.limit_val:
                result_items = result_items[:self.limit_val]
            return MockResponse(result_items)

        elif self.op == "update":
            updated_items = []
            for item in filtered_items:
                item.update(self.update_values)
                updated_items.append(item.copy())
            self.db.save_db()
            return MockResponse(updated_items)

        elif self.op == "delete":
            deleted_items = [item.copy() for item in filtered_items]
            self.db.set_table(self.table_name, remaining_items)
            return MockResponse(deleted_items)

class MockSupabaseClient:
    def __init__(self):
        self.db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "db.json")
        self.tables = {
            "users": [],
            "scan_history": [],
            "threat_logs": [],
            "settings": []
        }
        
        # Load existing data if file exists
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r", encoding="utf-8") as f:
                    self.tables.update(json.load(f))
            except Exception as e:
                print(f"[WARNING] Failed to load db.json: {str(e)}")

        # Seed default admin credentials if no users table records exist
        if not self.tables["users"]:
            from app.core.security import get_password_hash
            admin_id = "admin-uuid-1234"
            admin_hash = get_password_hash("admin123")
            self.tables["users"].append({
                "id": admin_id,
                "name": "Admin Operator",
                "email": "admin@stego.ai",
                "password_hash": admin_hash,
                "role": "admin",
                "is_permanent": True,
                "created_at": datetime.utcnow().isoformat() + "Z"
            })
            self.tables["settings"].append({
                "id": "settings-uuid-1234",
                "user_id": admin_id,
                "notifications_enabled": True,
                "alert_sound_enabled": True,
                "background_scan_enabled": True,
                "auto_scan_enabled": True,
                "dark_mode": True,
                "created_at": datetime.utcnow().isoformat() + "Z"
            })
            self.save_db()
        
        # Ensure existing admin user always has role + is_permanent fields
        for user in self.tables["users"]:
            if user.get("email") == "admin@stego.ai":
                if "role" not in user:
                    user["role"] = "admin"
                if "is_permanent" not in user:
                    user["is_permanent"] = True
            else:
                if "role" not in user:
                    user["role"] = "operator"
                if "is_permanent" not in user:
                    user["is_permanent"] = False
        self.save_db()

    def save_db(self):
        try:
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(self.tables, f, indent=2)
        except Exception as e:
            print(f"[WARNING] Failed to write db.json: {str(e)}")

    def get_table(self, table_name):
        return self.tables.get(table_name, [])

    def set_table(self, table_name, items):
        self.tables[table_name] = items
        self.save_db()

    def insert_row(self, table_name, record):
        row = record.copy()
        if "id" not in row:
            row["id"] = str(uuid.uuid4())
        if "created_at" not in row:
            row["created_at"] = datetime.utcnow().isoformat() + "Z"
        self.tables[table_name].append(row)
        self.save_db()
        return row

    def table(self, table_name):
        return MockQueryBuilder(table_name, self)

supabase = None

try:
    if "placeholder" in settings.SUPABASE_URL or "placeholder" in settings.SUPABASE_KEY or "your-project-id" in settings.SUPABASE_URL:
        print("\n[WARNING] Supabase is not configured. Running in local fallback/in-memory sandbox mode.\n")
        supabase = MockSupabaseClient()
    else:
        supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
except Exception as e:
    print(f"\n[WARNING] Supabase client initialization failed: {str(e)}")
    print("Running in local fallback/in-memory sandbox mode.\n")
    supabase = MockSupabaseClient()


