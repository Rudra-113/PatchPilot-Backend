from app.services.diff_service import generate_patch_diff


repository_id = "aa0d955f-8231-460a-8818-7d1a42e6e118"

patch = {
    "status": "PATCH_READY",
    "file": (
        f"scans/{repository_id}/"
        "patchpilot-sample/app.py"
    ),
    "old_code": (
        '    query = "SELECT id, username, email '
        'FROM users WHERE id = ?"\n'
    ),
    "new_code": (
        '    query = "SELECT id, username, email '
        'FROM users WHERE id = ?"\n'
    ),
}


result = generate_patch_diff(
    patch=patch,
    repository_path=f"scans/{repository_id}",
)


print("\n========== PATCH DIFF TEST ==========\n")
print(f"Status: {result.get('status')}")
print(f"Files changed: {result.get('files_changed')}")
print(f"Lines added: {result.get('lines_added')}")
print(f"Lines removed: {result.get('lines_removed')}")
print(f"Message: {result.get('message')}")

if result.get("diff"):
    print("\n---------- DIFF ----------\n")
    print(result["diff"])

print("\n======================================\n")