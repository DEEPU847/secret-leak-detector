import os
import stat

hook_script = """#!/bin/sh
echo "Running Secret Leak Detector..."
staged_files=$(git diff --cached --name-only --diff-filter=ACM)
if [ -z "$staged_files" ]; then
    exit 0
fi
python scanner.py $staged_files
exit $?
"""

def install():
    hooks_dir = ".git/hooks"
    if not os.path.exists(hooks_dir):
        print("Error: .git/hooks directory not found. Initialize git first.")
        return
    hook_path = os.path.join(hooks_dir, "pre-commit")
    with open(hook_path, "w") as f:
        f.write(hook_script)
    os.chmod(hook_path, os.stat(hook_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print("SUCCESS: Pre-commit hook installed successfully!")

if __name__ == "__main__":
    install()