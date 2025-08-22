import os
import tkinter as tk
from tkinter import messagebox, scrolledtext, Listbox, Toplevel, Label, Entry, Button
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import hashlib
import base64
import atexit
import random
import string
import json
import time
from datetime import datetime

# === Configuration ===
test_dir = 'sim_test'
password_file = 'password.txt'  # For simulation password
metadata_file = os.path.join(test_dir, 'metadata.json')  # Track file states
exfil_file = os.path.join(test_dir, 'exfiltrated_data.log')
key_dir = os.path.join(test_dir, 'keys')  # Store encrypted keys
num_simulated_files = 120  # >100 files

# Malicious marker to trigger ransomware
malicious_marker = "MALICIOUS_SIM_EXE_CONTENT"

# Realistic content templates
content_templates = [
    "Email: user{0}@example.com, Password: Pass{0}!\nLogin credentials for simulation.",
    "Bank Account: {0}-XXXX-XXXX, Routing: 98765{0}, Balance: ${1},000\nFake banking data.",
    "HR Record: Employee ID {0}, Salary: ${1}K, SSN: XXX-XX-{2}\nSynthetic PII.",
    "Medical Record: Patient {0}, Blood Type: {1}, Allergies: None\nDemo only.",
    "Device Log: User logged in from IP 192.168.1.{0} at {1}\nSystem simulation."
]

# Global key variables
private_key = None
public_key_pem = None
symmetric_key = None
generated_password = None


def create_test_dir_and_files(num_files=num_simulated_files):
    global private_key, public_key_pem, symmetric_key, generated_password

    # Setup directories
    os.makedirs(test_dir, exist_ok=True)
    os.makedirs(key_dir, exist_ok=True)

    # Generate RSA key pair once
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Serialize public key for distribution
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Generate password and symmetric key
    generated_password = generate_random_password() 
    symmetric_key = derive_symmetric_key(generated_password)

    # Save password (simulates attacker storing it)
    with open(password_file, 'w') as f:
        f.write(generated_password)

    # Initialize metadata
    metadata = {}

    for i in range(1, num_files + 1):
        file_name = f'sensitive_file_{i:03d}.txt'
        file_path = os.path.join(test_dir, file_name)

        # Choose template
        template_idx = (i % len(content_templates))
        content = content_templates[template_idx].format(
            i, random.randint(10, 99), ''.join(random.choices(string.digits, k=4))
        )

        # Inject malicious marker in a few files (e.g., file 001, 042, 088)
        if i in [1, 42, 88]:
            content = f"{malicious_marker}\n{content}\nTrigger ransomware on open."

        with open(file_path, 'w') as f:
            f.write(content)

        # Track metadata
        metadata[file_name] = {
            "status": "cleartext",
            "encrypted_at": None,
            "decrypted_at": None,
            "size": os.path.getsize(file_path),
            "created_at": datetime.now().isoformat(),
            "has_malicious_marker": i in [1, 42, 88],
            "rsa_encrypted_key_path": os.path.join(key_dir, f"{file_name}.key.enc")
        }

    # Save metadata
    save_metadata(metadata)
    log_text.insert(tk.END, f"✅ Created {num_files} simulated files with metadata tracking.\n")


def save_metadata(metadata):
    with open(metadata_file, 'w') as f:
        json.dump(metadata, f, indent=2)


def load_metadata():
    if os.path.exists(metadata_file):
        with open(metadata_file, 'r') as f:
            return json.load(f)
    return {}


def generate_random_password(length=8):
    """Generate an 8-digit random numeric password"""
    return ''.join(random.choices(string.digits, k=length))


def derive_symmetric_key(password):
    key = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(key[:32])


def encrypt_file(file_path, metadata_entry):
    global symmetric_key, public_key_pem

    # Read file data
    with open(file_path, 'rb') as f:
        file_data = f.read()

    fernet = Fernet(symmetric_key)
    encrypted_data = fernet.encrypt(file_data)

    public_key = serialization.load_pem_public_key(public_key_pem)
    encrypted_sym_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Save encrypted key separately
    with open(metadata_entry["rsa_encrypted_key_path"], 'wb') as key_file:
        key_file.write(encrypted_sym_key)

    # Overwrite file with encrypted data
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)

    # Update metadata
    metadata_entry["status"] = "encrypted"
    metadata_entry["encrypted_at"] = datetime.now().isoformat()
    save_metadata(load_metadata())


def decrypt_file(file_path, metadata_entry):
    # Load encrypted symmetric key
    key_path = metadata_entry["rsa_encrypted_key_path"]
    if not os.path.exists(key_path):
        raise FileNotFoundError("Encrypted key not found")

    with open(key_path, 'rb') as kf:
        encrypted_sym_key = kf.read()

    # Decrypt symmetric key with private RSA key
    decrypted_sym_key = private_key.decrypt(
        encrypted_sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    derived_key = base64.urlsafe_b64encode(decrypted_sym_key)

    # Decrypt file
    fernet = Fernet(derived_key)
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = fernet.decrypt(encrypted_data)

    with open(file_path, 'wb') as f:
        f.write(decrypted_data)

    # Update metadata
    metadata_entry["status"] = "decrypted"
    metadata_entry["decrypted_at"] = datetime.now().isoformat()
    save_metadata(load_metadata())


def exfiltrate_data():
    metadata = load_metadata()
    with open(exfil_file, 'a') as f:
        f.write(f"\n--- Exfiltration at {datetime.now().isoformat()} ---\n")
        for file_name, info in metadata.items():
            if "cleartext" in info["status"]:
                path = os.path.join(test_dir, file_name)
                if os.path.exists(path):
                    try:
                        with open(path, 'r', encoding='utf-8', errors='ignore') as src:
                            f.write(f"Exfiltrated {file_name}:\n{src.read()[:200]}...\n\n")
                    except:
                        f.write(f"Exfiltrated {file_name}: [Read failed]\n\n")
    log_text.insert(tk.END, "📡 Simulated data exfiltration complete.\n")


def trigger_encryption():
    log_text.insert(tk.END, "🔴 WARNING: Malicious content detected! Encrypting all files...\n")
    exfiltrate_data()

    metadata = load_metadata()
    count = 0
    for file_name, info in metadata.items():
        if info["status"] == "cleartext":
            file_path = os.path.join(test_dir, file_name)
            try:
                encrypt_file(file_path, info)
                log_text.insert(tk.END, f"🔒 Encrypted: {file_name}\n")
                count += 1
            except Exception as e:
                log_text.insert(tk.END, f"❌ Failed to encrypt {file_name}: {str(e)}\n")

    log_text.insert(tk.END, f"✅ Encrypted {count} files.\n")
    update_file_list()
    show_ransom_window()


def list_encrypted_files():
    metadata = load_metadata()
    return [f for f, info in metadata.items() if info["status"] == "encrypted"]


def list_cleartext_files():
    metadata = load_metadata()
    return [f for f, info in metadata.items() if info["status"] == "cleartext"]


def update_file_list():
    file_listbox.delete(0, tk.END)
    metadata = load_metadata()
    for file_name, info in metadata.items():
        status = info["status"].upper()
        file_listbox.insert(tk.END, f"{file_name} [{status}]")


def show_file_content():
    selected = file_listbox.curselection()
    if not selected:
        messagebox.showerror("Error", "Select a file first!")
        return

    full_name = file_listbox.get(selected[0])
    file_name = full_name.split(' [')[0]
    metadata = load_metadata()
    if file_name not in metadata:
        messagebox.showerror("Error", "File metadata missing!")
        return

    file_path = os.path.join(test_dir, file_name)
    if not os.path.exists(file_path):
        messagebox.showerror("Error", "File not found!")
        return

    # Check if malicious
    if metadata[file_name]["has_malicious_marker"]:
        trigger_encryption()
        return

    # Read and display
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        text_area.delete(1.0, tk.END)
        text_area.insert(tk.END, f"📄 Content of {file_name}:\n{content}")
    except Exception as e:
        text_area.insert(tk.END, f"Error reading file: {e}")


def decrypt_all_files(password):
    global private_key
    if password != generated_password:
        return False

    metadata = load_metadata()
    count = 0
    for file_name, info in metadata.items():
        if info["status"] == "encrypted":
            file_path = os.path.join(test_dir, file_name)
            try:
                decrypt_file(file_path, info)
                log_text.insert(tk.END, f"🔓 Decrypted: {file_name}\n")
                count += 1
            except Exception as e:
                log_text.insert(tk.END, f"❌ Failed to decrypt {file_name}: {str(e)}\n")

    log_text.insert(tk.END, f"✅ Decrypted {count} files.\n")
    update_file_list()
    log_text.insert(tk.END, "🎉 Simulation complete. All files recovered.\n")
    root.after(2000, root.quit)
    return True


def scan_all_files():
    metadata = load_metadata()
    files = sorted(metadata.keys())  # Process in order

    log_text.insert(tk.END, "🔍 Starting automated scan of all files...\n")
    root.update_idletasks()

    for file_name in files:
        file_path = os.path.join(test_dir, file_name)
        if not os.path.exists(file_path):
            continue

        # Simulate scanning delay for realism
        time.sleep(0.05)

        # Read file to check for malicious marker
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            log_text.insert(tk.END, f"✅ Scanned: {file_name}\n")
            root.update_idletasks()

            if malicious_marker in content:
                log_text.insert(tk.END, f"🔴 MALICIOUS FILE DETECTED: {file_name}\n")
                log_text.insert(tk.END, "🚨 Triggering ransomware simulation...\n")
                root.update_idletasks()
                time.sleep(1)

                # Stop scanning and trigger ransomware
                trigger_encryption()
                return  # Exit after triggering

        except Exception as e:
            log_text.insert(tk.END, f"❌ Error reading {file_name}: {str(e)}\n")

    # If no malicious file found
    log_text.insert(tk.END, "🟢 Scan complete: No malicious files detected.\n")


def show_ransom_window():
    ransom_win = Toplevel(root)
    ransom_win.title("🚨 RANSOMWARE SIMULATION")
    ransom_win.configure(bg='#8B0000')
    ransom_win.geometry("700x500")

    Label(ransom_win, text="ALL FILES ENCRYPTED", font=("Courier", 18, "bold"), bg='#8B0000', fg='red').pack(pady=10)
    Label(ransom_win, text="🔒", font=("Arial", 60), bg='#8B0000', fg='white').pack()

    msg = (
        "This is a simulation of a ransomware attack.\n"
        "Files were encrypted due to malicious content.\n\n"
        "To decrypt, enter the password shown in the log.\n"
        "No real files or data were harmed.\n\n"
        "Educational Purpose Only."
    )
    Label(ransom_win, text=msg, bg='#8B0000', fg='white', font=("Arial", 10), justify='center', wraplength=600).pack(pady=10)

    entry = Entry(ransom_win, width=50, font=("Arial", 12))
    entry.pack(pady=5)

    def submit():
        if decrypt_all_files(entry.get().strip()):
            ransom_win.destroy()
        else:
            messagebox.showerror("❌ Access Denied", "Incorrect decryption key.")

    Button(ransom_win, text="🔓 Submit Password", command=submit, bg='yellow', fg='black', font=("Arial", 12)).pack(pady=10)

    Label(ransom_win, text="⚠️ NEVER IGNORE UNTRUSTED FILES", font=("Arial", 9, "italic"), bg='#8B0000', fg='yellow').pack()


def show_help():
    help_win = Toplevel(root)
    help_win.title("📘 Help - Ransomware Simulation")
    help_win.geometry("500x400")

    help_text = (
        "🔐 Ransomware Simulation v2.0\n\n"
        "📁 Files: Over 100 synthetic files with realistic content (emails, bank data, PII).\n\n"
        "⚠️ Trigger: Opening a file with a malicious marker starts encryption.\n\n"
        "🔑 Key Management:\n"
        "   - RSA-2048 for key encryption\n"
        "   - AES-256 (Fernet) for file encryption\n"
        "   - Keys tracked via metadata\n\n"
        "📊 Metadata:\n"
        "   - Tracks file state (cleartext/encrypted/decrypted)\n"
        "   - Logs timestamps and key paths\n\n"
        "🛡️ Lessons:\n"
        "   - Scan files before opening\n"
        "   - Use backups\n"
        "   - Monitor for suspicious behavior"
    )
    Label(help_win, text=help_text, justify="left", font=("Arial", 10), wraplength=480).pack(pady=10)


def on_exit():
    print("✅ Ransomware simulation completed successfully.")
    print(f"📁 Test directory: {os.path.abspath(test_dir)}")
    print(f"🔑 Decryption password: {generated_password}")
    print(f"📊 Metadata: {metadata_file}")


atexit.register(on_exit)


# === GUI Setup ===
root = tk.Tk()
root.title("🔐 Ransomware Simulator: 100+ Files with Key & Metadata Tracking")
root.geometry("900x700")
root.configure(bg="#f0f0f0")

tk.Label(root, text="🔐 Educational Ransomware Simulation", font=("Helvetica", 16, "bold")).pack(pady=10)
tk.Label(root, text="Open a file with malicious content to trigger encryption.", fg="red").pack()

btn_frame = tk.Frame(root)
btn_frame.pack(pady=10)

Button(btn_frame, text="📁 Create 120 Files", command=create_test_dir_and_files, bg="blue", fg="white").grid(row=0, column=0, padx=5)
Button(btn_frame, text="📄 View Selected File", command=show_file_content, bg="green", fg="white").grid(row=0, column=1, padx=5)
Button(btn_frame, text="🔄 Scan All Files", command=scan_all_files, bg="orange", fg="white", font=("Arial", 9, "bold")).grid(row=0, column=2, padx=5)
Button(btn_frame, text="❓ Help", command=show_help, bg="gray", fg="white").grid(row=0, column=3, padx=5)

tk.Label(root, text="📂 Simulated Files (Status)", font=("Arial", 10, "bold")).pack()
file_listbox = Listbox(root, width=80, height=8)
file_listbox.pack(pady=5)

tk.Label(root, text="📄 File Content", font=("Arial", 10, "bold")).pack()
text_area = scrolledtext.ScrolledText(root, width=100, height=12)
text_area.pack(pady=5)

tk.Label(root, text="📋 Simulation Log", font=("Arial", 10, "bold")).pack()
log_text = scrolledtext.ScrolledText(root, width=100, height=12)
log_text.pack(pady=5)

# Initialize
create_test_dir_and_files()
update_file_list()

root.mainloop()