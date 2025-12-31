import base64
import re
import sys

def sha256_to_base64(sha256_input: str) -> str:
    """
    Convert SHA-256 digest (hex) to Base64.

    Supported input formats:
    - Plain hex (from apksigner)
    - Colon-separated hex (from keytool)
    """

    # Remove colons, spaces, and any non-hex characters
    clean_hex = re.sub(r'[^0-9a-fA-F]', '', sha256_input)

    if len(clean_hex) != 64:
        raise ValueError("Invalid SHA-256 digest length (expected 64 hex characters).")

    sha256_bytes = bytes.fromhex(clean_hex)
    return base64.b64encode(sha256_bytes).decode("utf-8")


def main():
    if len(sys.argv) != 2:
        print("Usage:")
        print("  python StrutterSignatureGen.py <SHA256_DIGEST>")
        print()
        print("Where to get SHA-256 digest:")
        print()
        print("1) From APK (apksigner)")
        print("   Command:")
        print("     apksigner verify --print-certs <apk>")
        print("   Take ONLY the value after:")
        print("     'SHA-256 digest:'")
        print()
        print("2) From Keystore (keytool)")
        print("   Command:")
        print("     keytool -list -v -keystore <keystore.jks>")
        print("   Take ONLY the value after:")
        print("     'SHA256:'")
        print()
        sys.exit(1)

    try:
        base64_signature = sha256_to_base64(sys.argv[1])
        print("Base64 Signature (SHA-256):")
        print(base64_signature)
    except Exception as e:
        print("Error:", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
