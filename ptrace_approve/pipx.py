#!/usr/bin/env python3
"""
ptrace-pipx: Install via pipx, then rewrite shebangs to run under ptrace-approve.
"""
import subprocess
import sys
import os
from pathlib import Path

PIPX_BIN_DIR = Path.home() / ".local" / "bin"

def resolve_package_name(arg):
    """Resolve a package name — handles '.' and paths by checking pipx list."""
    if arg in (".", "./") or arg.startswith("/") or arg.startswith("./"):
        result = subprocess.run(
            ["pipx", "list", "--json"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            import json
            data = json.loads(result.stdout)
            venvs = data.get("venvs", {})
            resolved = os.path.realpath(arg)
            for name, info in venvs.items():
                pkg_path = info.get("metadata", {}).get("main_package", {}).get("package_or_url", "")
                if pkg_path and os.path.realpath(pkg_path) == resolved:
                    return name
        return None
    return arg

def get_installed_scripts(package_name):
    """Find scripts installed by a pipx package."""
    result = subprocess.run(
        ["pipx", "list", "--json"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return []
    
    import json
    data = json.loads(result.stdout)
    venvs = data.get("venvs", {})
    pkg = venvs.get(package_name, {})
    metadata = pkg.get("metadata", {})
    apps = metadata.get("main_package", {}).get("apps", [])
    # also check injected packages
    for inj in metadata.get("injected_packages", {}).values():
        apps.extend(inj.get("apps", []))
    return apps

def rewrite_shebang(script_path):
    """Rewrite a script's shebang to wrap with ptrace-approve."""
    path = Path(script_path)
    if not path.exists():
        print(f"  skip: {path} not found")
        return False
    
    with open(path, "rb") as f:
        first_line = f.readline()
        rest = f.read()
    
    if not first_line.startswith(b"#!"):
        print(f"  skip: {path} has no shebang")
        return False
    
    shebang = first_line.decode("utf-8", errors="replace").strip()
    
    # Already wrapped?
    if "ptrace-approve" in shebang:
        print(f"  skip: {path} already wrapped")
        return False
    
    # Extract the interpreter from the shebang
    # #!/path/to/python -> /path/to/python
    # #!/usr/bin/env python3 -> we need to keep env usage
    interpreter = shebang[2:].strip()
    
    # Use the script's absolute path as the profile (don't follow symlinks)
    profile_name = str(path.absolute())
    
    new_shebang = f"#!/usr/bin/env -S ptrace-approve --profile {profile_name} {interpreter}\n"
    
    with open(path, "wb") as f:
        f.write(new_shebang.encode("utf-8"))
        f.write(rest)
    
    print(f"  rewrote: {path}")
    print(f"    old: {shebang}")
    print(f"    new: {new_shebang.strip()}")
    return True

def unwrap_shebang(script_path):
    """Remove ptrace-approve from a script's shebang."""
    path = Path(script_path)
    if not path.exists():
        return False
    
    with open(path, "rb") as f:
        first_line = f.readline()
        rest = f.read()
    
    if not first_line.startswith(b"#!"):
        return False
    
    shebang = first_line.decode("utf-8", errors="replace").strip()
    
    if "ptrace-approve" not in shebang:
        print(f"  skip: {path} not wrapped")
        return False
    
    # #!/usr/bin/env -S ptrace-approve --profile NAME /path/to/python -> #!/path/to/python
    import re
    interpreter = re.sub(r'^#!/usr/bin/env -S ptrace-approve\s+(--profile\s+\S+\s+)?', '#!', shebang)
    
    with open(path, "wb") as f:
        f.write(f"{interpreter}\n".encode("utf-8"))
        f.write(rest)
    
    print(f"  unwrapped: {path}")
    return True

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  ptrace-pipx install PACKAGE    Install via pipx and wrap shebangs")
        print("  ptrace-pipx wrap PACKAGE       Wrap shebangs for already-installed package")
        print("  ptrace-pipx unwrap PACKAGE     Remove ptrace-approve from shebangs")
        print("  ptrace-pipx list               List wrapped packages")
        print("")
        print("All other arguments are passed through to pipx.")
        sys.exit(1)
    
    cmd = sys.argv[1]
    
    if cmd == "install":
        # Pass through to pipx, capturing output to extract package name
        result = subprocess.run(["pipx"] + sys.argv[1:], capture_output=True, text=True)
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        if result.returncode != 0:
            sys.exit(result.returncode)
        
        # Find the package name
        package = None
        for arg in sys.argv[2:]:
            if not arg.startswith("-"):
                package = resolve_package_name(arg)
                break
        
        # Fallback: parse "installed package NAME" from pipx output
        if not package:
            import re
            m = re.search(r'installed package (\S+)', result.stdout)
            if m:
                package = m.group(1)
        
        if not package:
            print("Could not determine package name")
            sys.exit(1)
        
        scripts = get_installed_scripts(package)
        if not scripts:
            print(f"No scripts found for {package}")
            sys.exit(0)
        
        print(f"\nWrapping {len(scripts)} script(s) with ptrace-approve:")
        for script in scripts:
            script_path = PIPX_BIN_DIR / script
            rewrite_shebang(script_path)
    
    elif cmd == "wrap":
        if len(sys.argv) < 3:
            print("Usage: ptrace-pipx wrap PACKAGE")
            sys.exit(1)
        package = resolve_package_name(sys.argv[2])
        if not package:
            print(f"Could not resolve package: {sys.argv[2]}")
            sys.exit(1)
        scripts = get_installed_scripts(package)
        if not scripts:
            print(f"No scripts found for {package}")
            sys.exit(1)
        
        print(f"Wrapping {len(scripts)} script(s) with ptrace-approve:")
        for script in scripts:
            script_path = PIPX_BIN_DIR / script
            rewrite_shebang(script_path)
    
    elif cmd == "unwrap":
        if len(sys.argv) < 3:
            print("Usage: ptrace-pipx unwrap PACKAGE")
            sys.exit(1)
        package = resolve_package_name(sys.argv[2])
        if not package:
            print(f"Could not resolve package: {sys.argv[2]}")
            sys.exit(1)
        scripts = get_installed_scripts(package)
        if not scripts:
            print(f"No scripts found for {package}")
            sys.exit(1)
        
        print(f"Unwrapping {len(scripts)} script(s):")
        for script in scripts:
            script_path = PIPX_BIN_DIR / script
            unwrap_shebang(script_path)
    
    elif cmd == "list":
        # Scan bin dir for wrapped scripts
        wrapped = []
        for f in sorted(PIPX_BIN_DIR.iterdir()):
            if not f.is_file():
                continue
            try:
                with open(f, "rb") as fh:
                    line = fh.readline(200)
                if b"ptrace-approve" in line:
                    wrapped.append(f.name)
            except Exception:
                pass
        
        if wrapped:
            print("Wrapped scripts:")
            for name in wrapped:
                print(f"  {name}")
        else:
            print("No wrapped scripts found.")
    
    else:
        # Pass everything through to pipx
        result = subprocess.run(["pipx"] + sys.argv[1:])
        sys.exit(result.returncode)

if __name__ == "__main__":
    main()