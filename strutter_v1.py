import os
import sys
import subprocess
import json
import hashlib
import time
import random
import string
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

# Strutter v0.1 – Hardening Tools for Flutter Android
TOOL_NAME = "Strutter"
TOOL_VERSION = "0.1"
CONFIG_FILE = "hardening_config.json"
TEMPLATE_ROOT = "strutter_plugin_config"

# Global state
global_config = None
config_exists = False
integration_guide_open = False
selected_plugins = {"root": True, "frida": True, "integrity": True}

if getattr(sys, 'frozen', False):
    application_path = os.path.dirname(sys.executable)
else:
    application_path = os.path.dirname(os.path.abspath(__file__))

TEMPLATE_ROOT = os.path.join(application_path, "strutter_plugin_config")

if not os.path.exists(TEMPLATE_ROOT):
    messagebox.showerror(
        "Template Missing",
        "Folder 'strutter_plugin_config' not found.\n"
        "Please place it in the same directory as strutter.exe / strutter.py"
    )
    sys.exit(1)

def plugin_name_to_class_name(plugin_name):
    if plugin_name.endswith("_plugin"):
        base = plugin_name[:-7]
        return base[0].upper() + base[1:] + "Plugin"
    return plugin_name + "Plugin"

def run_command(cmd, cwd=None):
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=60, cwd=cwd
        )
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        return stdout, stderr, result.returncode
    except Exception as e:
        return "", str(e), -1

def check_flutter():
    out, err, code = run_command("flutter --version")
    if code != 0:
        return False, f"Flutter CLI not found or failed to run.\nError: {err}"
    if not out or not out.strip():
        return False, "Flutter command returned empty output."
    try:
        version_line = out.strip().split("\n")[0]
        version = version_line.split()[1] if len(version_line.split()) > 1 else "unknown"
        return True, f"Flutter version {version} detected."
    except Exception as e:
        return False, f"Failed to parse Flutter version.\nOutput: {out}\nError: {str(e)}"

def validate_flutter_project(path):
    if not os.path.isdir(path):
        return False, "Path is not a directory."
    pubspec = os.path.join(path, "pubspec.yaml")
    if not os.path.exists(pubspec):
        return False, "pubspec.yaml not found. Not a valid Flutter project."
    return True, "Valid Flutter project."

def is_valid_strict_structure(project_path):
    current_dir = os.path.abspath(os.getcwd())
    current_name = os.path.basename(current_dir)
    if current_name != "STRUTTER":
        return False, "This tool must be run from a folder named exactly 'STRUTTER'."
    parent_dir = os.path.dirname(current_dir)
    project_abs = os.path.abspath(project_path)
    project_parent = os.path.dirname(project_abs)
    if os.path.normpath(parent_dir) != os.path.normpath(project_parent):
        expected = os.path.basename(parent_dir)
        return False, (
            f"Project must be a direct sibling of 'STRUTTER'.\n\n"
            f"Expected structure:\n"
            f"  {expected}/\n"
            f"    ├── STRUTTER/\n"
            f"    └── <YourProject>/\n\n"
            f"Selected project is not in the same parent folder."
        )
    return True, "Structure is valid."

def generate_plugin_identifier(seed_input):
    hash_hex = hashlib.md5(seed_input.encode("utf-8")).hexdigest()
    letter_index = int(hash_hex[:2], 16) % 26
    prefix_letter = string.ascii_lowercase[letter_index]
    return prefix_letter + hash_hex

def load_config_at_startup():
    global global_config, config_exists, selected_plugins
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                data = json.load(f)
                global_config = data
                config_exists = True
                if "selected_plugins" in data:
                    selected_plugins = data["selected_plugins"]
                else:
                    selected_plugins = {"root": True, "frida": True, "integrity": True}
        except Exception:
            global_config = None
            config_exists = False
            selected_plugins = {"root": True, "frida": True, "integrity": True}
    else:
        config_exists = False
        global_config = None
        selected_plugins = {"root": True, "frida": True, "integrity": True}

def create_plugins(log_callback):
    base_seed = f"strutter_{int(time.time())}_{random.randint(100000, 999999)}"
    config = {
        "tool": f"{TOOL_NAME} v{TOOL_VERSION}",
        "selected_plugins": selected_plugins,
        "plugins": {}
    }
    for key in ["frida", "root", "integrity"]:
        if selected_plugins.get(key, False):
            if key == "frida":
                config["plugins"][key] = generate_plugin_identifier(base_seed + "_frida_detection")
            elif key == "root":
                config["plugins"][key] = generate_plugin_identifier(base_seed + "_root_detection")
            elif key == "integrity":
                config["plugins"][key] = generate_plugin_identifier(base_seed + "_integrity_check")
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)
    global global_config, config_exists
    global_config = config
    config_exists = True
    names = []
    for key in ["frida", "root", "integrity"]:
        if selected_plugins.get(key, False):
            names.append(f"{config['plugins'][key]}_plugin")
    success = True
    for name in names:
        log_callback(f"Creating plugin: {name} ...\n")
        cmd = f'flutter create --template=plugin --platforms=android "{name}"'
        out, err, code = run_command(cmd)
        if code == 0:
            log_callback(f"✓ Success: {name}\n")
        else:
            log_callback(f"✗ Failed: {name}\nError: {err}\n")
            success = False
    return success

def apply_plugin_template(plugin_type, has_manifest=True):
    global global_config, config_exists
    if not config_exists or not global_config or "plugins" not in global_config:
        return False, "No configuration found. Run Step 1 first."
    if plugin_type not in global_config["plugins"]:
        return False, f"{plugin_type.capitalize()} plugin not selected."
    plugin_id = global_config["plugins"][plugin_type]
    plugin_name = f"{plugin_id}_plugin"
    plugin_path = os.path.abspath(plugin_name)
    if not os.path.exists(plugin_path):
        return False, f"{plugin_type.capitalize()} plugin directory not found: {plugin_path}"
    type_config = {
        "frida": {
            "old_package": "frida_detection_nodbg_v1_plugin",
            "old_class": "FridaDetectionNodbgV1Plugin",
            "dir": "FRIDA",
            "kt": "FRIDA_1.kt",
            "dart": "FRIDA_2.dart",
            "manifest": "FRIDA_MANIFEST.xml"
        },
        "root": {
            "old_package": "root_detection_nodbg_v1_plugin",
            "old_class": "RootDetectionNodbgV1Plugin",
            "dir": "ROOT",
            "kt": "ROOT_1.kt",
            "dart": "ROOT_2.dart",
            "manifest": "ROOT_MANIFEST.xml"
        },
        "integrity": {
            "old_package": "integrity_check_nodbg_v1_plugin",
            "old_class": "IntegrityCheckNodbgV1Plugin",
            "dir": "INTEGRITY",
            "kt": "INTEGRITY_1.kt",
            "dart": "INTEGRITY_2.dart",
            "manifest": None
        }
    }
    cfg = type_config[plugin_type]
    template_dir = os.path.join(TEMPLATE_ROOT, cfg["dir"])
    kt_template = os.path.join(template_dir, cfg["kt"])
    dart_template = os.path.join(template_dir, cfg["dart"])
    manifest_template = os.path.join(template_dir, cfg["manifest"]) if has_manifest else None
    missing = []
    if not os.path.exists(kt_template):
        missing.append(cfg["kt"])
    if not os.path.exists(dart_template):
        missing.append(cfg["dart"])
    if has_manifest and not os.path.exists(manifest_template):
        missing.append(cfg["manifest"])
    if missing:
        return False, f"Missing {plugin_type} template(s): {', '.join(missing)}"
    kt_file = None
    kt_search_dir = os.path.join(plugin_path, "android", "src", "main", "kotlin")
    if os.path.exists(kt_search_dir):
        for root, _, files in os.walk(kt_search_dir):
            for f in files:
                if f.endswith(".kt"):
                    kt_file = os.path.join(root, f)
                    break
            if kt_file:
                break
    if not kt_file:
        return False, f"Kotlin file not found for {plugin_type} plugin."
    dart_file = os.path.join(plugin_path, "lib", f"{plugin_name}.dart")
    if not os.path.exists(dart_file):
        return False, f"Dart file not found: {dart_file}"
    try:
        with open(kt_template, "r", encoding="utf-8") as f:
            kt_content = f.read()
        with open(dart_template, "r", encoding="utf-8") as f:
            dart_content = f.read()
        manifest_content = None
        if has_manifest:
            with open(manifest_template, "r", encoding="utf-8") as f:
                manifest_content = f.read()
    except Exception as e:
        return False, f"Failed to read {plugin_type} templates: {str(e)}"
    new_package = plugin_name
    new_class = plugin_name_to_class_name(plugin_name)
    kt_content = kt_content.replace(cfg["old_package"], new_package)
    kt_content = kt_content.replace(cfg["old_class"], new_class)
    dart_content = dart_content.replace(cfg["old_package"], new_package)
    dart_content = dart_content.replace(cfg["old_class"], new_class)
    if has_manifest:
        manifest_content = manifest_content.replace(cfg["old_package"], new_package)
    try:
        with open(kt_file, "w", encoding="utf-8") as f:
            f.write(kt_content)
        with open(dart_file, "w", encoding="utf-8") as f:
            f.write(dart_content)
        if has_manifest:
            manifest_file = os.path.join(plugin_path, "android", "src", "main", "AndroidManifest.xml")
            os.makedirs(os.path.dirname(manifest_file), exist_ok=True)
            with open(manifest_file, "w", encoding="utf-8") as f:
                f.write(manifest_content)
    except Exception as e:
        return False, f"Failed to write {plugin_type} files: {str(e)}"
    return True, f"{plugin_type.capitalize()} template applied successfully."

def apply_selected_plugins():
    applied = []
    errors = []
    for plugin_type in ["root", "frida", "integrity"]:
        if global_config and "plugins" in global_config and plugin_type in global_config["plugins"]:
            success, msg = apply_plugin_template(plugin_type, has_manifest=(plugin_type != "integrity"))
            if success:
                applied.append(plugin_type)
            else:
                errors.append(msg)
    if errors:
        log_area.insert(tk.END, "⚠️ Some plugins failed:\n" + "\n".join(errors) + "\n")
        messagebox.showwarning("Partial Success", "Some plugins applied successfully.")
    else:
        log_area.insert(tk.END, f"✓ All selected plugins applied: {', '.join(applied)}\n")
        messagebox.showinfo("Success", f"Plugins applied: {', '.join(applied)}")
    return len(applied) > 0

def apply_dependencies_to_pubspec():
    global global_config
    if not global_config or "flutter_project" not in global_config:
        messagebox.showerror("Error", "Flutter project not set. Please set it first.")
        return False
    project_path = global_config["flutter_project"]
    pubspec_path = os.path.join(project_path, "pubspec.yaml")
    if not os.path.exists(pubspec_path):
        messagebox.showerror("Error", "pubspec.yaml not found in project.")
        return False
    plugins_to_add = []
    for key in ["frida", "root", "integrity"]:
        if global_config.get("plugins", {}).get(key):
            plugin_name = f"{global_config['plugins'][key]}_plugin"
            rel_path = os.path.relpath(
                os.path.abspath(plugin_name),
                project_path
            ).replace("\\", "/")
            plugins_to_add.append((plugin_name, rel_path))
    if not plugins_to_add:
        messagebox.showwarning("Warning", "No plugins generated yet.")
        return False
    try:
        with open(pubspec_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read pubspec.yaml: {str(e)}")
        return False
    dep_start = -1
    for i, line in enumerate(lines):
        if line.strip().startswith("dependencies:"):
            dep_start = i + 1
            break
    if dep_start == -1:
        messagebox.showerror("Error", "dependencies section not found in pubspec.yaml")
        return False
    dep_end = len(lines)
    base_indent = None
    for i in range(dep_start, len(lines)):
        line = lines[i]
        if line.strip() == "" or line.strip().startswith("#"):
            continue
        if not line.startswith(" "):
            dep_end = i
            break
        if base_indent is None:
            base_indent = len(line) - len(line.lstrip(" "))
        else:
            current_indent = len(line) - len(line.lstrip(" "))
            if current_indent <= base_indent:
                dep_end = i
                break
    dep_lines = lines[dep_start:dep_end]
    filtered_dep_lines = []
    i = 0
    while i < len(dep_lines):
        line = dep_lines[i]
        is_hardening_plugin = False
        for name, _ in plugins_to_add:
            if line.strip().startswith(f"{name}:"):
                is_hardening_plugin = True
                if i + 1 < len(dep_lines) and "path:" in dep_lines[i + 1]:
                    i += 1
                break
        if not is_hardening_plugin:
            filtered_dep_lines.append(line)
        i += 1
    new_entries = []
    for name, rel_path in plugins_to_add:
        new_entries.append(f"  {name}:\n")
        new_entries.append(f"    path: {rel_path}\n")
    new_dep_lines = filtered_dep_lines + new_entries
    new_lines = lines[:dep_start] + new_dep_lines + lines[dep_end:]
    try:
        with open(pubspec_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
        log_area.insert(tk.END, f"✓ Dependencies added to:\n  {pubspec_path}\n")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to write pubspec.yaml: {str(e)}")
        return False
    return True

def check_dependencies_applied():
    global global_config
    if not global_config or "flutter_project" not in global_config:
        return False, "Flutter project not set."
    project_path = global_config["flutter_project"]
    pubspec_path = os.path.join(project_path, "pubspec.yaml")
    if not os.path.exists(pubspec_path):
        return False, "pubspec.yaml not found."
    try:
        with open(pubspec_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        return False, "Failed to read pubspec.yaml."
    applied_count = 0
    total_expected = 0
    for key in ["frida", "root", "integrity"]:
        if global_config.get("plugins", {}).get(key):
            total_expected += 1
            plugin_name = f"{global_config['plugins'][key]}_plugin"
            if f"{plugin_name}:" in content:
                applied_count += 1
    return applied_count == total_expected, f"{applied_count}/{total_expected} applied"

def update_ndk_version():
    global global_config
    if not global_config or "flutter_project" not in global_config:
        messagebox.showerror("Error", "Flutter project not set.")
        return False, ""
    project_path = global_config["flutter_project"]
    gradle_path = os.path.join(project_path, "android", "app", "build.gradle.kts")
    if not os.path.exists(gradle_path):
        messagebox.showerror("Error", "build.gradle.kts not found.")
        return False, ""
    try:
        with open(gradle_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read build.gradle.kts: {str(e)}")
        return False, ""
    android_block_start = -1
    for i, line in enumerate(lines):
        if "android {" in line:
            android_block_start = i
            break
    if android_block_start == -1:
        messagebox.showerror("Error", "'android {' block not found in build.gradle.kts")
        return False, ""
    ndk_line_index = -1
    for i in range(android_block_start + 1, len(lines)):
        line = lines[i]
        if line.strip().startswith("}"):
            break
        if "ndkVersion" in line:
            ndk_line_index = i
            break
    target_ndk = 'ndkVersion = "27.0.12077973"'
    if ndk_line_index != -1:
        lines[ndk_line_index] = f"    {target_ndk}\n"
        log_msg = "✓ NDK version updated."
    else:
        insert_index = android_block_start + 1
        lines.insert(insert_index, f"    {target_ndk}\n")
        log_msg = "✓ NDK version added."
    try:
        with open(gradle_path, "w", encoding="utf-8") as f:
            f.writelines(lines)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to write build.gradle.kts: {str(e)}")
        return False, ""
    return True, log_msg

def run_apply_dependencies():
    apply_dep_btn.config(state="disabled")
    root.update_idletasks()
    try:
        dep_ok, dep_msg = check_dependencies_applied()
        if dep_ok:
            proceed = messagebox.askyesno(
                "Dependencies Already Applied",
                "All hardening plugins are already in pubspec.yaml.\n\n"
                "Update paths again?"
            )
            if not proceed:
                log_area.insert(tk.END, "ℹ️ Dependencies already applied. Skipped.\n")
                return
        success = apply_dependencies_to_pubspec()
        if success:
            log_area.insert(tk.END, "✓ Dependencies applied to pubspec.yaml\n")
            messagebox.showinfo("Success", "Hardening plugins added to pubspec.yaml.")
            update_dashboard()
        else:
            log_area.insert(tk.END, "✗ Failed to apply dependencies.\n")
    finally:
        apply_dep_btn.config(state="normal")

def run_set_ndk():
    ndk_btn.config(state="disabled")
    pubget_btn.config(state="disabled")
    root.update_idletasks()
    try:
        success, msg = update_ndk_version()
        if success:
            project_path = global_config["flutter_project"]
            gradle_path = os.path.join(project_path, "android", "app", "build.gradle.kts")
            log_area.insert(tk.END, f"✓ NDK version set in:\n  {gradle_path}\n")
            pubget_btn.config(state="normal")
        else:
            log_area.insert(tk.END, "✗ Failed to set NDK version.\n")
    finally:
        ndk_btn.config(state="normal")

def run_flutter_pub_get():
    global global_config
    if not global_config or "flutter_project" not in global_config:
        messagebox.showerror("Error", "Flutter project not set.")
        return False
    project_path = global_config["flutter_project"]
    out, err, code = run_command("flutter pub get", cwd=project_path)
    if code == 0:
        log_area.insert(tk.END, "✓ flutter pub get: Success\n")
        messagebox.showinfo("Success", "Dependencies installed successfully!")
        return True
    else:
        log_area.insert(tk.END, f"✗ flutter pub get failed:\n{err}\n")
        messagebox.showerror("Error", f"flutter pub get failed:\n{err}")
        return False

def run_pub_get():
    pubget_btn.config(state="disabled")
    root.update_idletasks()
    try:
        success = run_flutter_pub_get()
        if success:
            integration_btn.config(state="normal")
    finally:
        pubget_btn.config(state="normal")

def start_step1():
    log_area.delete(1.0, tk.END)
    log_area.insert(tk.END, f"{TOOL_NAME} v{TOOL_VERSION} – Starting Step 1\n")
    flutter_ok, msg = check_flutter()
    log_area.insert(tk.END, msg + "\n")
    if not flutter_ok:
        messagebox.showerror("Error", msg)
        return
    success = create_plugins(lambda m: log_area.insert(tk.END, m))
    if success:
        messagebox.showinfo("Completed", f"{TOOL_NAME} v{TOOL_VERSION}: Plugin generation completed.")
        update_dashboard()
        step1_btn.config(state="disabled", text="Plugins Already Generated", bg="#BDBDBD")
        apply_plugins_btn.config(state="normal")
    else:
        messagebox.showwarning("Warning", "One or more plugins failed to generate.")

def run_apply_selected_plugins():
    apply_plugins_btn.config(state="disabled")
    root.update_idletasks()
    try:
        success = apply_selected_plugins()
        if success:
            log_area.insert(tk.END, "✓ Selected plugins applied.\n")
        else:
            log_area.insert(tk.END, "✗ No plugins to apply.\n")
    finally:
        apply_plugins_btn.config(state="normal")

def update_dashboard():
    dashboard_area.delete(1.0, tk.END)
    
    if config_exists and global_config:
        dashboard_area.insert(tk.END, f"Status: Locked\n")
        dashboard_area.insert(tk.END, f"Tool: {global_config.get('tool', 'Unknown')}\n\n")
        
        plugins = global_config.get("plugins", {})
        if plugins:
            dashboard_area.insert(tk.END, "Plugins:\n")
            for key in ["frida", "root", "integrity"]:
                if key in plugins:
                    name = "Frida" if key == "frida" else "Root" if key == "root" else "Integrity"
                    dashboard_area.insert(tk.END, f"• {name}: {plugins[key]}\n")
            dashboard_area.insert(tk.END, "\n")
        
        proj_path = global_config.get("flutter_project")
        if proj_path:
            dashboard_area.insert(tk.END, f"Project: {os.path.basename(proj_path)}\n")
            dep_ok, _ = check_dependencies_applied()
            dep_text = "✓ Applied" if dep_ok else "⚠️ Not Applied"
            dashboard_area.insert(tk.END, f"Dependencies: {dep_text}\n")
            dashboard_area.insert(tk.END, f"Project Path: {proj_path}\n\n")
        
        dashboard_area.insert(tk.END, "NDK Version: 27.0.12077973\n")
    else:
        dashboard_area.insert(tk.END, "Status: Ready\n")
        dashboard_area.insert(tk.END, "Run Step 1 to initialize.\n")

def browse_project_folder():
    from tkinter import filedialog
    folder_selected = filedialog.askdirectory(title="Select Flutter Project Folder")
    if folder_selected:
        project_entry.delete(0, tk.END)
        project_entry.insert(0, folder_selected)

def validate_and_save_project():
    path = project_entry.get().strip()
    if not path:
        messagebox.showwarning("Input Required", "Please enter or select a Flutter project path.")
        return
    abs_path = os.path.abspath(path)
    is_flutter, msg = validate_flutter_project(abs_path)
    if not is_flutter:
        messagebox.showerror("Invalid Path", msg)
        log_area.insert(tk.END, f"✗ Invalid Flutter project: {msg}\n")
        return
    is_valid, structure_msg = is_valid_strict_structure(abs_path)
    if not is_valid:
        messagebox.showerror("Invalid Folder Structure", structure_msg)
        log_area.insert(tk.END, f"✗ {structure_msg}\n")
        return
    global global_config, config_exists
    if global_config is None:
        global_config = {"tool": f"{TOOL_NAME} v{TOOL_VERSION}", "selected_plugins": selected_plugins, "plugins": {}}
    global_config["flutter_project"] = abs_path
    with open(CONFIG_FILE, "w") as f:
        json.dump(global_config, f, indent=2)
    config_exists = True
    update_dashboard()
    messagebox.showinfo("Success", "Flutter project path saved.")
    log_area.insert(tk.END, f"✓ Flutter project set: {abs_path}\n")

# === INTEGRATION CODE GENERATORS ===
def generate_root_code(mode="exit"):
    if not global_config or "plugins" not in global_config or "root" not in global_config["plugins"]:
        return "", "", ""
    plugin_name = f'{global_config["plugins"]["root"]}_plugin'
    class_name = plugin_name_to_class_name(plugin_name)
    import_code = f"import 'package:{plugin_name}/{plugin_name}.dart';"
    if mode == "exit":
        action = "        exit(0);"
    elif mode == "popup":
        action = '''        WidgetsBinding.instance.addPostFrameCallback((_) {
          showDialog(
            context: context,
            barrierDismissible: false,
            builder: (_) => AlertDialog(
              title: Text("DEVICE ROOTED"),
              content: Text("Device is rooted or compromised. The app will close."),
              actions: [
                TextButton(onPressed: () => exit(0), child: Text("OK"))
              ],
            ),
          );
        });'''
    else:
        action = '        print("❌ Root detected");'
    method_code = f'''Future<void> _checkRoot() async {{
  try {{
    final rooted = await {class_name}.isDeviceRooted;
    if (rooted) {{
{action}
    }} else {{
      print("✅ No root detected");
    }}
  }} catch (e) {{
    print("⚠️ Error during root check: $e");
  }}
}}'''
    init_code = '''@override
void initState() {
  super.initState();
  _checkRoot();
}'''
    return import_code, method_code, init_code

def generate_frida_code(mode="exit"):
    if not global_config or "plugins" not in global_config or "frida" not in global_config["plugins"]:
        return "", "", ""
    plugin_name = f'{global_config["plugins"]["frida"]}_plugin'
    class_name = plugin_name_to_class_name(plugin_name)
    import_code = f"import 'package:{plugin_name}/{plugin_name}.dart';"
    if mode == "exit":
        action = "        exit(0);"
    elif mode == "popup":
        action = '''        WidgetsBinding.instance.addPostFrameCallback((_) {
          showDialog(
            context: context,
            barrierDismissible: false,
            builder: (_) => AlertDialog(
              title: Text("FRIDA DETECTED"),
              content: Text("Frida or instrumentation detected. The app will close."),
              actions: [
                TextButton(onPressed: () => exit(0), child: Text("OK"))
              ],
            ),
          );
        });'''
    else:
        action = '        print("❌ FRIDA detected");'
    method_code = f'''Future<void> _checkFrida() async {{
  try {{
    final detected = await {class_name}.isFridaDetected;
    if (detected) {{
{action}
    }} else {{
      print("✅ Frida not detected");
    }}
  }} catch (e) {{
    print("⚠️ Error during frida check: $e");
  }}
}}'''
    init_code = '''@override
void initState() {
  super.initState();
  _checkFrida();
}'''
    return import_code, method_code, init_code

def generate_integrity_code(signatures, mode="exit"):
    if not global_config or "plugins" not in global_config or "integrity" not in global_config["plugins"]:
        return "", "", ""
    plugin_name = f'{global_config["plugins"]["integrity"]}_plugin'
    class_name = plugin_name_to_class_name(plugin_name)
    import_code = f"import 'package:{plugin_name}/{plugin_name}.dart';"
    sig_lines = ",\n  ".join(f'"{s.strip()}"' for s in signatures if s.strip())
    sig_list = f"final List<String> validSignatures = [\n  {sig_lines}\n];"
    if mode == "exit":
        action_invalid = "        exit(0);"
        action_error = "      exit(0);"
    elif mode == "popup":
        action_invalid = '''        WidgetsBinding.instance.addPostFrameCallback((_) {
          showDialog(
            context: context,
            barrierDismissible: false,
            builder: (_) => AlertDialog(
              title: Text("SIGNATURE NOT VALID"),
              actions: [TextButton(onPressed: () => exit(0), child: Text("OK"))]
            )
          );
        });'''
        action_error = '''      WidgetsBinding.instance.addPostFrameCallback((_) {
        showDialog(
          context: context,
          barrierDismissible: false,
          builder: (_) => AlertDialog(
            title: Text("INTEGRITY CHECK ERROR"),
            actions: [TextButton(onPressed: () => exit(0), child: Text("OK"))]
          )
        );
      });'''
    else:
        action_invalid = '        print("❌ SIGNATURE NOT VALID: $sig");'
        action_error = '      print("⚠️ Error during integrity check: $e");'
    method_code = f'''{sig_list}

Future<void> _checkIntegrity() async {{
  try {{
    final sig = await {class_name}.getApkSignature();
    final valid = validSignatures.contains(sig);
    if (!valid) {{
{action_invalid}
    }} else {{
      print("✅ SIGNATURE VALID");
    }}
  }} catch (e) {{
{action_error}
  }}
}}'''
    init_code = '''@override
void initState() {
  super.initState();
  _checkIntegrity();
}'''
    return import_code, method_code, init_code

def copy_to_clipboard(text):
    root.clipboard_clear()
    root.clipboard_append(text)
    messagebox.showinfo("Copied", "Code copied to clipboard!")

def open_integration_guide():
    global integration_guide_open
    if integration_guide_open:
        return
    if not global_config or "plugins" not in global_config:
        messagebox.showwarning("Warning", "No plugins generated yet. Run Step 1 and Apply Plugins first.")
        return
        
    integration_window = tk.Toplevel(root)
    integration_window.title("Integration Guide")
    integration_window.geometry("820x620")
    integration_guide_open = True
    
    def on_close():
        global integration_guide_open
        integration_guide_open = False
        integration_window.destroy()
    
    integration_window.protocol("WM_DELETE_WINDOW", on_close)
    
    root_mode = tk.StringVar(value="exit")
    frida_mode = tk.StringVar(value="exit")
    integrity_mode = tk.StringVar(value="exit")
    
    tab_control = ttk.Notebook(integration_window)
    
    has_root = "root" in global_config["plugins"]
    has_frida = "frida" in global_config["plugins"]
    has_integrity = "integrity" in global_config["plugins"]
    
    if has_root:
        root_tab = ttk.Frame(tab_control)
        tab_control.add(root_tab, text="Root")
    if has_frida:
        frida_tab = ttk.Frame(tab_control)
        tab_control.add(frida_tab, text="Frida")
    if has_integrity:
        integrity_tab = ttk.Frame(tab_control)
        tab_control.add(integrity_tab, text="Integrity")
    
    if not (has_root or has_frida or has_integrity):
        tk.Label(integration_window, text="No plugins selected for integration.", font=("Arial", 12)).pack(pady=20)
        return
        
    tab_control.pack(expand=1, fill="both")
    
    # === ROOT TAB ===
    if has_root:
        tk.Label(root_tab, text="Root Detection Mode:", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10, pady=(10,5))
        tk.Radiobutton(root_tab, text="Exit", variable=root_mode, value="exit").pack(anchor="w", padx=20)
        tk.Radiobutton(root_tab, text="Popup", variable=root_mode, value="popup").pack(anchor="w", padx=20)
        tk.Radiobutton(root_tab, text="Log Only", variable=root_mode, value="log").pack(anchor="w", padx=20)

        tk.Label(root_tab, text="ℹ️ Note: If using Exit or Popup mode, add\nimport 'dart:io'; in your main.dart", 
             font=("Segoe UI", 8), fg="#555", justify=tk.LEFT).pack(anchor="w", padx=20, pady=(5,10))
        
        root_import_out = scrolledtext.ScrolledText(root_tab, height=1, font=("Consolas", 9))
        root_method_out = scrolledtext.ScrolledText(root_tab, height=10, font=("Consolas", 9))
        root_init_out = scrolledtext.ScrolledText(root_tab, height=3, font=("Consolas", 9))
        
        def generate_root():
            imp, meth, init = generate_root_code(root_mode.get())
            root_import_out.delete(1.0, tk.END)
            root_import_out.insert(1.0, imp)
            root_method_out.delete(1.0, tk.END)
            root_method_out.insert(1.0, meth)
            root_init_out.delete(1.0, tk.END)
            root_init_out.insert(1.0, init)
        
        tk.Button(root_tab, text="Generate Code", command=generate_root, bg="#4CAF50", fg="white", relief="flat").pack(pady=10)
        tk.Label(root_tab, text="IMPORT:", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10)
        root_import_out.pack(padx=10, fill=tk.X)
        tk.Button(root_tab, text="Copy", command=lambda: copy_to_clipboard(root_import_out.get(1.0, tk.END).strip()), bg="#2196F3", fg="white", relief="flat").pack(pady=2)
        tk.Label(root_tab, text="METHOD:", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10, pady=(10,0))
        root_method_out.pack(padx=10, fill=tk.BOTH, expand=True)
        tk.Button(root_tab, text="Copy", command=lambda: copy_to_clipboard(root_method_out.get(1.0, tk.END).strip()), bg="#2196F3", fg="white", relief="flat").pack(pady=2)
        tk.Label(root_tab, text="INIT STATE SNIPPET:", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10, pady=(10,0))
        root_init_out.pack(padx=10, fill=tk.X)
        tk.Button(root_tab, text="Copy", command=lambda: copy_to_clipboard(root_init_out.get(1.0, tk.END).strip()), bg="#2196F3", fg="white", relief="flat").pack(pady=2)
        generate_root()
    
    # === FRIDA TAB ===
    if has_frida:
        tk.Label(frida_tab, text="Frida Detection Mode:", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10, pady=(10,5))
        tk.Radiobutton(frida_tab, text="Exit", variable=frida_mode, value="exit").pack(anchor="w", padx=20)
        tk.Radiobutton(frida_tab, text="Popup", variable=frida_mode, value="popup").pack(anchor="w", padx=20)
        tk.Radiobutton(frida_tab, text="Log Only", variable=frida_mode, value="log").pack(anchor="w", padx=20)

        tk.Label(frida_tab, text="ℹ️ Note: If using Exit or Popup mode, add\nimport 'dart:io'; in your main.dart", 
             font=("Segoe UI", 8), fg="#555", justify=tk.LEFT).pack(anchor="w", padx=20, pady=(5,10))
        
        frida_import_out = scrolledtext.ScrolledText(frida_tab, height=1, font=("Consolas", 9))
        frida_method_out = scrolledtext.ScrolledText(frida_tab, height=10, font=("Consolas", 9))
        frida_init_out = scrolledtext.ScrolledText(frida_tab, height=3, font=("Consolas", 9))
        
        def generate_frida():
            imp, meth, init = generate_frida_code(frida_mode.get())
            frida_import_out.delete(1.0, tk.END)
            frida_import_out.insert(1.0, imp)
            frida_method_out.delete(1.0, tk.END)
            frida_method_out.insert(1.0, meth)
            frida_init_out.delete(1.0, tk.END)
            frida_init_out.insert(1.0, init)
        
        tk.Button(frida_tab, text="Generate Code", command=generate_frida, bg="#4CAF50", fg="white", relief="flat").pack(pady=10)
        tk.Label(frida_tab, text="IMPORT:", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10)
        frida_import_out.pack(padx=10, fill=tk.X)
        tk.Button(frida_tab, text="Copy", command=lambda: copy_to_clipboard(frida_import_out.get(1.0, tk.END).strip()), bg="#2196F3", fg="white", relief="flat").pack(pady=2)
        tk.Label(frida_tab, text="METHOD:", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10, pady=(10,0))
        frida_method_out.pack(padx=10, fill=tk.BOTH, expand=True)
        tk.Button(frida_tab, text="Copy", command=lambda: copy_to_clipboard(frida_method_out.get(1.0, tk.END).strip()), bg="#2196F3", fg="white", relief="flat").pack(pady=2)
        tk.Label(frida_tab, text="INIT STATE SNIPPET:", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10, pady=(10,0))
        frida_init_out.pack(padx=10, fill=tk.X)
        tk.Button(frida_tab, text="Copy", command=lambda: copy_to_clipboard(frida_init_out.get(1.0, tk.END).strip()), bg="#2196F3", fg="white", relief="flat").pack(pady=2)
        generate_frida()
    
    # === INTEGRITY TAB ===
    if has_integrity:
        tk.Label(integrity_tab, text="Valid APK Signatures (one per line):", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10, pady=(10,5))
        sig_text = tk.Text(integrity_tab, height=5, width=70, font=("Consolas", 9))
        sig_text.insert("1.0", "XmQivnL4J8QvvzwD1bUoZrxtHRidUZLXikknwreG7ec=")
        sig_text.pack(padx=10, pady=(0,10))
        
        tk.Label(integrity_tab, text="Integrity Check Mode:", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10, pady=(10,5))
        tk.Radiobutton(integrity_tab, text="Exit", variable=integrity_mode, value="exit").pack(anchor="w", padx=20)
        tk.Radiobutton(integrity_tab, text="Popup", variable=integrity_mode, value="popup").pack(anchor="w", padx=20)
        tk.Radiobutton(integrity_tab, text="Log Only", variable=integrity_mode, value="log").pack(anchor="w", padx=20)

        tk.Label(frida_tab, text="ℹ️ Note: If using Exit or Popup mode, add\nimport 'dart:io'; in your main.dart", 
             font=("Segoe UI", 8), fg="#555", justify=tk.LEFT).pack(anchor="w", padx=20, pady=(5,10))
        
        integrity_import_out = scrolledtext.ScrolledText(integrity_tab, height=1, font=("Consolas", 9))
        integrity_method_out = scrolledtext.ScrolledText(integrity_tab, height=12, font=("Consolas", 9))
        integrity_init_out = scrolledtext.ScrolledText(integrity_tab, height=3, font=("Consolas", 9))
        
        def generate_integrity():
            sigs = sig_text.get("1.0", tk.END).strip().split("\n")
            imp, meth, init = generate_integrity_code(sigs, integrity_mode.get())
            integrity_import_out.delete(1.0, tk.END)
            integrity_import_out.insert(1.0, imp)
            integrity_method_out.delete(1.0, tk.END)
            integrity_method_out.insert(1.0, meth)
            integrity_init_out.delete(1.0, tk.END)
            integrity_init_out.insert(1.0, init)
        
        tk.Button(integrity_tab, text="Generate Code", command=generate_integrity, bg="#4CAF50", fg="white", relief="flat").pack(pady=10)
        tk.Label(integrity_tab, text="IMPORT:", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10)
        integrity_import_out.pack(padx=10, fill=tk.X)
        tk.Button(integrity_tab, text="Copy", command=lambda: copy_to_clipboard(integrity_import_out.get(1.0, tk.END).strip()), bg="#2196F3", fg="white", relief="flat").pack(pady=2)
        tk.Label(integrity_tab, text="METHOD:", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10, pady=(10,0))
        integrity_method_out.pack(padx=10, fill=tk.BOTH, expand=True)
        tk.Button(integrity_tab, text="Copy", command=lambda: copy_to_clipboard(integrity_method_out.get(1.0, tk.END).strip()), bg="#2196F3", fg="white", relief="flat").pack(pady=2)
        tk.Label(integrity_tab, text="INIT STATE SNIPPET:", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10, pady=(10,0))
        integrity_init_out.pack(padx=10, fill=tk.X)
        tk.Button(integrity_tab, text="Copy", command=lambda: copy_to_clipboard(integrity_init_out.get(1.0, tk.END).strip()), bg="#2196F3", fg="white", relief="flat").pack(pady=2)
        generate_integrity()

def on_enter(e):
    e.widget.config(bg="#1976D2")
def on_leave(e):
    e.widget.config(bg="#2196F3")

# === UI ===
load_config_at_startup()
root = tk.Tk()
root.title(f"{TOOL_NAME} v{TOOL_VERSION}")
root.geometry("960x840")
root.configure(bg="white")

header_frame = tk.Frame(root, bg="white")
header_frame.pack(pady=12)
tk.Label(header_frame, text=f"{TOOL_NAME} v{TOOL_VERSION}", font=("Segoe UI", 16, "bold"), bg="white", fg="#212121").pack()
tk.Label(header_frame, text="Flutter Hardening Toolkit for Android", font=("Segoe UI", 10), bg="white", fg="#616161").pack(pady=(4,0))

tk.Label(root, text="SELECT PLUGINS TO GENERATE", font=("Segoe UI", 10, "bold"), bg="white", fg="#212121", anchor="w").pack(anchor="w", padx=30, pady=(15,5))
plugin_frame = tk.Frame(root, bg="white")
plugin_frame.pack(pady=5)
root_var = tk.BooleanVar(value=selected_plugins["root"])
frida_var = tk.BooleanVar(value=selected_plugins["frida"])
integrity_var = tk.BooleanVar(value=selected_plugins["integrity"])
tk.Checkbutton(plugin_frame, text="Root Detection", variable=root_var, command=lambda: selected_plugins.update({"root": root_var.get()}), bg="white", font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=15)
tk.Checkbutton(plugin_frame, text="Frida Detection", variable=frida_var, command=lambda: selected_plugins.update({"frida": frida_var.get()}), bg="white", font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=15)
tk.Checkbutton(plugin_frame, text="Integrity Check", variable=integrity_var, command=lambda: selected_plugins.update({"integrity": integrity_var.get()}), bg="white", font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=15)

step1_btn = tk.Button(
    root, text="Step 1: Generate Plugins", command=start_step1,
    bg="#2196F3", fg="white", font=("Segoe UI", 10, "bold"), padx=20, pady=8, relief="flat", bd=0
)
if config_exists:
    step1_btn.config(state="disabled", text="Plugins Already Generated", bg="#BDBDBD")
else:
    step1_btn.bind("<Enter>", on_enter)
    step1_btn.bind("<Leave>", on_leave)
step1_btn.pack(pady=10)

project_frame = tk.Frame(root, bg="white")
project_frame.pack(pady=15, padx=30, fill=tk.X)
tk.Label(project_frame, text="FLUTTER PROJECT FOLDER", font=("Segoe UI", 10, "bold"), bg="white", anchor="w").pack(anchor="w")
tk.Label(project_frame, text="(Must be a direct sibling of STRUTTER)", font=("Segoe UI", 9), bg="white", fg="#616161", anchor="w").pack(anchor="w", pady=(0,5))

input_browse_frame = tk.Frame(project_frame, bg="white")
input_browse_frame.pack(pady=5, fill=tk.X)
project_entry = tk.Entry(input_browse_frame, width=70, font=("Consolas", 9))
project_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,10))
browse_btn = tk.Button(input_browse_frame, text="Browse...", command=browse_project_folder, bg="#607D8B", fg="white", relief="flat", bd=0)
browse_btn.pack(side=tk.RIGHT)

validate_btn = tk.Button(project_frame, text="Validate & Save Project Path", command=validate_and_save_project, bg="#03A9F4", fg="white", font=("Segoe UI", 10), padx=15, pady=5, relief="flat", bd=0)
validate_btn.bind("<Enter>", lambda e: e.widget.config(bg="#0288D1"))
validate_btn.bind("<Leave>", lambda e: e.widget.config(bg="#03A9F4"))
validate_btn.pack(pady=(10, 15))

apply_plugins_btn = tk.Button(
    project_frame,
    text="Step 2: Apply Selected Plugins",
    command=run_apply_selected_plugins,
    bg="#2196F3", fg="white", font=("Segoe UI", 10, "bold"), padx=15, pady=6, relief="flat", bd=0
)
apply_plugins_btn.pack(pady=(0, 10))
apply_plugins_btn.config(state="disabled")
apply_plugins_btn.bind("<Enter>", on_enter)
apply_plugins_btn.bind("<Leave>", on_leave)

apply_dep_btn = tk.Button(
    project_frame, 
    text="Step 3: Apply Dependencies to pubspec.yaml", 
    command=run_apply_dependencies,
    bg="#2196F3", fg="white", font=("Segoe UI", 10, "bold"), padx=15, pady=6, relief="flat", bd=0
)
apply_dep_btn.pack(pady=(0, 8))
apply_dep_btn.bind("<Enter>", on_enter)
apply_dep_btn.bind("<Leave>", on_leave)

ndk_btn = tk.Button(
    project_frame,
    text="Step 4: Set NDK Version (27.0.12077973)",
    command=run_set_ndk,
    bg="#2196F3", fg="white", font=("Segoe UI", 10, "bold"), padx=15, pady=6, relief="flat", bd=0
)
ndk_btn.pack(pady=(0, 8))
ndk_btn.bind("<Enter>", on_enter)
ndk_btn.bind("<Leave>", on_leave)

pubget_btn = tk.Button(
    project_frame,
    text="Step 5: Run flutter pub get",
    command=run_pub_get,
    bg="#2196F3", fg="white", font=("Segoe UI", 10, "bold"), padx=15, pady=6, relief="flat", bd=0
)
pubget_btn.pack(pady=(0, 15))
pubget_btn.config(state="disabled")
pubget_btn.bind("<Enter>", on_enter)
pubget_btn.bind("<Leave>", on_leave)

integration_btn = tk.Button(
    root,
    text="Step 6: Show Integration Guide",
    command=open_integration_guide,
    bg="#2196F3", fg="white", font=("Segoe UI", 10, "bold"), padx=15, pady=6, relief="flat", bd=0,
    state="disabled"
)
integration_btn.pack(pady=(0, 10))
integration_btn.bind("<Enter>", on_enter)
integration_btn.bind("<Leave>", on_leave)

main_frame = tk.Frame(root, bg="white")
main_frame.pack(padx=20, pady=(0, 20), fill=tk.BOTH, expand=True)

log_frame = tk.Frame(main_frame, bg="white")
log_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
tk.Label(log_frame, text="ACTIVITY LOG", font=("Segoe UI", 10, "bold"), bg="white", anchor="w").pack(anchor="w", padx=5)
log_area = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, font=("Consolas", 9), bg="#F5F5F5", relief="solid", bd=1)
log_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=(5,0))

dashboard_frame = tk.Frame(main_frame, bg="white")
dashboard_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
tk.Label(dashboard_frame, text="DASHBOARD", font=("Segoe UI", 10, "bold"), bg="white", anchor="w").pack(anchor="w", padx=5)
dashboard_area = scrolledtext.ScrolledText(dashboard_frame, wrap=tk.WORD, font=("Consolas", 9), bg="#F5F5F5", relief="solid", bd=1)
dashboard_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=(5,0))

update_dashboard()

root.mainloop()