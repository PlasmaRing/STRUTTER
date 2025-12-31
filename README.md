# Strutter v0.1 – Flutter Hardening Toolkit for Android

**Strutter** is a Python-based GUI tool that automates the generation, integration, and configuration of security hardening plugins for Flutter Android applications. It helps developers protect their apps against common reverse engineering threats such as **rooted devices**, **Frida instrumentation**, and **APK tampering**.

The tool **generates obfuscated plugins**, attaches them to your Flutter project, configures build settings (e.g., NDK version), and provides step-by-step integration guidance all through an intuitive interface.

**Strutter** is a Python-based GUI tool that automates the generation and integration of security hardening plugins for Flutter Android applications. It helps developers establish a **first line of defense** against common mobile threats including **rooted devices, Frida-based dynamic instrumentation, APK tampering**, and **network interception** by combining multiple detection layers.

The tool **generates obfuscated plugins**, attaches them to your Flutter project, configures critical build settings (e.g., NDK version), and provides clear, copy-paste integration guidance.

> ⚠️ Note: Hardening techniques are **not 100% foolproof**; they aim to raise the attack cost and deter casual reverse engineering, not guarantee absolute security.

---

## ✅ Tested Environment

- **Flutter**: 3.32.8
- **Dart**: 3.8.1
- **Android SDK**: 24 (Android 7.0) to 36 (Android 16)
- **Platforms**: Android (physical & emulator)

> The tool is designed for **Flutter Android apps** and assumes a standard Flutter project structure.

---

## 📁 Repository Structure

```
STRUTTER/
├── strutter_v1.py             # Main GUI application (source)
├── Strutter.exe               # Standalone executable (Windows)
├── StruttersSignatureGen.py   # Utility to extract APK signatures (optional)
└── strutter_plugin_config/    # Plugin templates (required at runtime)
    ├── FRIDA/
    ├── ROOT/
    └── INTEGRITY/
```

> 🔸 `strutter_plugin_config/` **must be placed in the same directory as `Strutter.exe`** when distributing the tool.

---

## 🚀 How to Use

1. **Place your Flutter project** in a folder **sibling to `STRUTTER`**:
   ```
   YourWorkspace/
   ├── STRUTTER/
   └── MyApp/          ← your Flutter project (with pubspec.yaml)
   ```

2. **Run `Strutter.exe`** (or `python strutter_v1.py`)

3. **Follow the 6-step workflow**:
   - **Step 1**: Select plugins (Root, Frida, Integrity) and generate them.
   - **Step 2**: Choose your Flutter project folder and validate the structure.
   - **Step 3**: Apply selected plugins with obfuscated identifiers.
   - **Step 4**: Inject dependencies into `pubspec.yaml`.
   - **Step 5**: Set NDK version to `27.0.12077973` in `build.gradle.kts`.
   - **Step 6**: Run `flutter pub get` and open the **Integration Guide** to copy Dart code snippets.

4. **Copy the integration code** from the guide into your `main.dart`. Each plugin requires **three components**:
- **IMPORT**: Add the plugin import at the top of your file.
- **METHOD**: Paste the detection method (e.g., `_checkRoot()`).
- **INIT STATE SNIPPET**: Call the method inside `initState()`.

5. **Build and test** your hardened APK.

---

## 📌 Notes

- The tool **does not modify your `main.dart` automatically** — integration is manual for safety and transparency.
- Plugin names are **obfuscated** using a 1-letter prefix + full MD5 hash (e.g., `x7e2f..._plugin`) to resist static analysis.
- Signature validation (Integrity Check) requires **Base64-encoded SHA-256 certificate digest** from your release APK (use `StruttersSignatureGen.py` or `apksigner` to extract it).
- **Not compatible with Flutter Web/iOS** (uses `dart:io` and native Android checks).

---

## 🛠️ Build from Source

```bash
pip install pyinstaller
pyinstaller --noconsole --onefile strutter_v1.py
```

> Make sure `strutter_plugin_config/` is in the same directory as the generated `dist/Strutter.exe`.

---

## 📄 License

This project is for academic and defensive security research purposes. Use responsibly.

```
Copyright (c) 2025 – Strutter Hardening Toolkit
```

---

> 🔐 **Hardening is not a silver bullet — it’s one layer in a defense-in-depth strategy.**
