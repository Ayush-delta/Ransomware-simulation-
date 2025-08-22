# 🔐 Ransomware Simulation (Educational) — Tkinter GUI

**Purpose:** This repository contains an **educational** ransomware simulation that demonstrates how file encryption, key management, exfiltration, and metadata tracking might work in a controlled lab environment.  
**Audience:** Students, trainers, blue-teamers, and security enthusiasts.  
**⚠️ Disclaimer:** This code is for **learning and demo purposes only**. Do **not** use it on real/production systems or against data you cannot afford to lose.

---

## ✨ Features

- **GUI with Tkinter**: One-click buttons to create files, scan, view, and simulate ransomware behavior.
- **120+ synthetic files**: Realistic-looking content (emails, HR data, logs, etc.).
- **Detonation Trigger**: Opening a file that contains a malicious marker simulates a ransomware event.
- **Hybrid Crypto**:
  - **AES-256 (Fernet)** for file content.
  - **RSA-2048** public key crypto to encrypt the symmetric key (per file, stored separately).
- **Metadata Tracking** (`metadata.json`): State per file (`cleartext`/`encrypted`/`decrypted`), timestamps, key paths, sizes, flags.
- **Simulated Exfiltration**: Appends previews of cleartext files to `exfiltrated_data.log` before encryption.
- **Ransom Window**: Shows a decryption password prompt (educational only).

---

## 🧭 How It Works (High-Level)

1. **Setup**  
   - On start or via the **Create 120 Files** button, the app generates:
     - A **random 8-digit password** (the “decryption key” shown in the console/log).
     - A **symmetric key** derived from that password (`SHA-256` → URL-safe base64 → used by Fernet).
     - A single **RSA keypair** (in-memory). Its **public key** encrypts the symmetric key for each file; the **private key** is kept in memory only.
     - 120 synthetic files in `sim_test/`, plus a `keys/` directory for RSA-encrypted symmetric keys.
     - `metadata.json` to track file state and provenance.
2. **Trigger**  
   - Viewing a file that contains the special marker `MALICIOUS_SIM_EXE_CONTENT` simulates malware execution and **encrypts all files**.
3. **Encrypt**  
   - Each file is encrypted with **Fernet (AES-256)**. The corresponding symmetric key is encrypted with **RSA-OAEP (SHA-256)** and stored at `sim_test/keys/<file>.key.enc`.
   - File states are updated in `metadata.json`.
4. **Exfiltrate**  
   - Before encryption, previews of **cleartext** files are appended to `exfiltrated_data.log` (simulated “exfil” event).
5. **Ransom Window**  
   - A red window appears asking for the **8-digit password** printed in the log. Entering the correct password **decrypts** all files.

---

## 📦 Requirements

- **Python**: 3.9+ recommended
- **Libraries**:
  - `cryptography` (install via `pip`)
  - `tkinter` (bundled with most Python distributions; on Linux you may need `python3-tk`)
- **OS**: Windows, macOS, or Linux (GUI required)

```bash
pip install cryptography
# On Debian/Ubuntu if needed:
# sudo apt-get install python3-tk
```

---

## 🚀 Running the Simulation

1. **Save the provided script** (e.g., `ransomware_sim.py`).
2. **Install dependencies** as above.
3. **Run the app**:
   ```bash
   python ransomware_sim.py
   ```
4. In the GUI:
   - Click **“📁 Create 120 Files”** to initialize the lab.
   - Click **“📄 View Selected File”** to open a file from the list.
     - If you open a file that contains the malicious marker (e.g., files **001**, **042**, **088**), it will **trigger encryption**.
   - Click **“🔄 Scan All Files”** to simulate an AV scan—encryption will trigger if a malicious file is detected.
   - Use the **Ransom Window** to enter the **8-digit password** shown in the terminal/log to decrypt the files.

**Where to look**:
- Test files: `sim_test/`
- RSA-encrypted keys: `sim_test/keys/`
- Metadata: `sim_test/metadata.json`
- Simulated exfiltration log: `sim_test/exfiltrated_data.log`
- Simulation password: printed in the terminal at exit and saved to `password.txt` (for demo only)

---

## 🧰 Directory Structure

```
.
├── ransomware_sim.py
└── sim_test/
    ├── sensitive_file_001.txt
    ├── sensitive_file_002.txt
    ├── ...
    ├── metadata.json
    ├── exfiltrated_data.log
    └── keys/
        ├── sensitive_file_001.txt.key.enc
        ├── sensitive_file_002.txt.key.enc
        └── ...
```

---

## ⚙️ Configuration (top of script)

- `test_dir = 'sim_test'` — lab folder for generated files.
- `password_file = 'password.txt'` — stores the generated demo password.
- `metadata_file = os.path.join(test_dir, 'metadata.json')`
- `exfil_file = os.path.join(test_dir, 'exfiltrated_data.log')`
- `key_dir = os.path.join(test_dir, 'keys')`
- `num_simulated_files = 120`
- `malicious_marker = "MALICIOUS_SIM_EXE_CONTENT"`

You can safely tweak the **number of files**, **marker**, and **paths**.

---

## 🧪 Simulation Flow (Detailed)

- **Initialization**: Generates RSA keypair (in-memory), password, and per-file metadata.
- **Viewing/Scanning**: If a file contains the **malicious marker**, the simulation will:
  1. Append previews of cleartext data to `exfiltrated_data.log`.
  2. Encrypt all cleartext files with **Fernet (AES)**.
  3. Encrypt the **symmetric key** with **RSA-OAEP** per file into `keys/<file>.key.enc`.
  4. Update `metadata.json` with status/timestamps.
  5. Display a **ransom window**.
- **Decryption**: Enter the correct **8-digit password** in the ransom window to decrypt all files and restore to `cleartext` state.

---

## 🧱 Security Lessons & Talking Points

- Importance of **file scanning** before opening suspicious content.
- Clear **separation of data and keys**; hybrid cryptography model in ransomware.
- **Metadata** aids IR/forensics and state management.
- **Backups** and **offline copies** are critical for resilience.
- **User training**: recognizing suspicious triggers and unexpected UI prompts.

---

## 🩺 Troubleshooting

- **GUI won’t launch**: Ensure Tkinter is installed (`python3-tk` on Linux).
- **“Incorrect decryption key”**: Use the 8-digit password printed in the console or found in `password.txt`.
- **Files not appearing**: Click **Create 120 Files** first, or check write permissions to `sim_test/`.
- **Unicode read errors**: The app opens files with `errors='ignore'` to avoid crashes; this is expected for mixed content.

---

## 🔧 Extending the Lab

- Add more **content templates** (CSV, PDFs, images) and additional **file types**.
- Introduce **timer-based triggers**, **network beacons**, or **process monitors**.
- Swap Fernet for another **AES mode** or integrate **XChaCha20-Poly1305** for comparison.
- Model **partial encryption** (headers only) or **multi-stage** workflows.
- Export richer **telemetry** for SOC practice.

---

## ⚖️ Legal & Ethics

This repository is strictly for **defensive security education**. Running real ransomware or using this code to harm others is illegal and unethical. Use in **isolated lab environments** only.

---

---

## 🙌 Credits

- Built with **Python**, **Tkinter**, and **cryptography**.
- Created as an educational demo to illustrate ransomware kill chains and defenses.
