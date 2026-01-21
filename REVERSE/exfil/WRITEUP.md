# Exfil 500 - Write-up

## Challenge Overview
**Objective**: Recover the flag `IDEH{...}` from the provided Android project/APK.
**Hint**: "Easy but hard & chaining is key".

## Analysis

### 1. Initial Reconnaissance
The project contains standard Android source code. Searching for the string "IDEH" reveals interesting hits:
- `app/src/main/assets/docs/index.html`: An offline documentation page.
- `app/src/main/java/com/cit/ideh/exfil/DocsActivity.java`: The activity that loads the HTML.

### 2. The Vulnerability Chain
The "chaining is key" hint refers to the flow found in `DocsActivity.java`:
1.  **XSS**: The activity takes a URL parameter (or intent data) and injects it into the `index.html` via `window.setQuery(q)`. This allows for Cross-Site Scripting (XSS).
2.  **Javascript Interface**: The WebView exposes a method via `addJavascriptInterface(new a(...), "IDEH")`.
3.  **Exfiltration**: An attacker can use XSS to call `IDEH.readVault()`.

### 3. Decryption Logic
The core secret is hidden in the `readVault()` method (implemented in `i1.a.java`):
-   It reads an encrypted binary resource: `app/src/main/res/raw/flag_blob.bin`.
-   It retrieves the **APK's Signing Certificate** (`getApkContentsSigners`).
-   It calculates the **SHA-256 hash** of the certificate.
-   It uses the first **16 bytes** of the hash as an **AES-GCM key** to decrypt the blob.

### 4. The Obstacle
If you are working with the decompiled source (e.g., from Jadx), the original `META-INF` folder containing the signature (`CERT.RSA` or similar) is often missing or stripped. Without the original signature, you cannot derive the key to decrypt the flag.

### 5. Solution
To solve this, we need the original `.apk` file to extract the implementation's true signature.

**Steps:**
1.  **Analyze APK Signature**: The provided `exfil.apk` is signed using **APK Signature Scheme v2**. This means the signature is stored in a binary block before the ZIP Central Directory, not just in `META-INF`.
2.  **Extract Certificate**: We parse the APK binary to find the APK Signing Block (Magic: `APK Sig Block 42`) and extract the X.509 certificate from the V2 signature block.
3.  **Decrypt**: We use the extracted certificate to derive the key and decrypt `flag_blob.bin`.

## Solver Script

Here is a Python script that performs the decryption given the certificate and the encrypted blob.

```python
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography import x509

# Configuration
# Path to the binary blob found in app/src/main/res/raw/flag_blob.bin
FLAG_BLOB_PATH = "flag_blob.bin" 
# Path to the extracted certificate (DER or PEM format)
CERT_PATH = "cert.der"
AAD = b"com.cit.ideh.exfil"

def solve():
    # 1. Read Encrypted Blob
    try:
        with open(FLAG_BLOB_PATH, "rb") as f:
            blob = f.read()
    except FileNotFoundError:
        print(f"[-] Missing {FLAG_BLOB_PATH}")
        return

    iv = blob[:12]
    ciphertext = blob[12:]

    # 2. Derive Key from Certificate
    try:
        with open(CERT_PATH, "rb") as f:
            cert_data = f.read()
            
        # Attempt to load as DER, fallback to PEM
        try:
            cert = x509.load_der_x509_certificate(cert_data)
        except:
            cert = x509.load_pem_x509_certificate(cert_data)
            
        # Get raw bytes (DER)
        der_bytes = cert.public_bytes(serialization.Encoding.DER)
        
        # Key = SHA256(cert_bytes)[:16]
        key = hashlib.sha256(der_bytes).digest()[:16]
        print(f"[+] Derived Key: {key.hex()}")
        
    except Exception as e:
        print(f"[-] Certificate Error: {e}")
        return

    # 3. Decrypt
    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(iv, ciphertext, AAD)
        print(f"\n[+] FLAG: {plaintext.decode()}")
    except Exception as e:
        print(f"[-] Decryption Failed: {e}")

if __name__ == "__main__":
    solve()
```

## Flag
Running the solution with the certificate extracted from the original APK yields:

**`IDEH{m4ster_0f_4ndro1d}`**
