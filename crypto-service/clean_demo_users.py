import sqlite3
import json
import os

db_path = 'crypto-service/data/ledger.db'
conn = sqlite3.connect(db_path)
cur = conn.cursor()

# Remove all non-head users
cur.execute("DELETE FROM users WHERE role != 'head'")
cur.execute("DELETE FROM sessions WHERE username NOT IN ('head', 'admin')")
cur.execute("DELETE FROM security_notifications")
conn.commit()

remaining = cur.execute("SELECT id, username, role FROM users").fetchall()
print("Remaining users in DB:", remaining)
conn.close()

# Clear demo public registry
registry_path = 'crypto-service/data/keystore/public_registry.json'
with open(registry_path, 'w') as f:
    json.dump({}, f, indent=2)
print("public_registry.json cleared.")

dist_path = 'crypto-service/data/keystore/distribution_store.json'
if os.path.exists(dist_path):
    with open(dist_path, 'w') as f:
        json.dump({}, f, indent=2)
    print("distribution_store.json cleared.")

tardos_path = 'crypto-service/data/keystore/tardos_documents.json'
if os.path.exists(tardos_path):
    with open(tardos_path, 'w') as f:
        json.dump({}, f, indent=2)
    print("tardos_documents.json cleared.")
