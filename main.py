"""
main.py — OS-Level Secure File System: Interactive CLI Entry Point

This is a PURE OS-LEVEL application. No web server, no browser, no HTTP.
All operations interact directly with the local operating system.

Run with:  python main.py
"""

import os
import sys
import getpass
import tempfile

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(__file__))

from modules import auth, filesystem, permissions, encryption, process_mgmt, sharing, audit_log

# ── Terminal Colors (no external library needed) ───────────────────────────────
try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    RED    = Fore.RED
    GREEN  = Fore.GREEN
    YELLOW = Fore.YELLOW
    CYAN   = Fore.CYAN + Style.BRIGHT
    BLUE   = Fore.BLUE + Style.BRIGHT
    WHITE  = Fore.WHITE + Style.BRIGHT
    MAGENTA= Fore.MAGENTA + Style.BRIGHT
    RESET  = Style.RESET_ALL
    DIM    = Style.DIM
except ImportError:
    RED = GREEN = YELLOW = CYAN = BLUE = WHITE = MAGENTA = RESET = DIM = ""

BANNER = f"""
{CYAN}╔══════════════════════════════════════════════════════════════╗
║     OS-LEVEL SECURE FILE MANAGEMENT SYSTEM                   ║
║     Direct OS API Edition — Python / POSIX / Win32           ║
╠══════════════════════════════════════════════════════════════╣
║  OS Concepts: syscalls · file descriptors · process IDs      ║
║               chmod · ACL · fork/exec · O_APPEND · stat()   ║
╚══════════════════════════════════════════════════════════════╝{RESET}
"""

LOGGED_OUT_MENU = f"""
{WHITE}── Authentication ──────────────────────────────────────────────{RESET}
  {GREEN}1{RESET}. Register new user
  {GREEN}2{RESET}. Login
  {GREEN}0{RESET}. Exit
"""

LOGGED_IN_MENU_TEMPLATE = """
{cyan}── Logged in as: {user}  (Session PID={pid}) ───────────────────────{reset}
{white}── File Operations ─────────────────────────────────────────────{reset}
  {g}3{r}. Upload & Encrypt a file         {g}4{r}. List my files
  {g}5{r}. Download & Decrypt a file        {g}6{r}. Delete a file

{white}── Permissions & Sharing ────────────────────────────────────────{reset}
  {g}7{r}. View file permissions            {g}8{r}. chmod (change permissions)
  {g}9{r}. Share file with another user    {g}10{r}. Revoke shared access

{white}── OS Internals ─────────────────────────────────────────────────{reset}
 {g}11{r}. Show file stat() info (inode/mode/times)
 {g}12{r}. Run malware scan in child process
 {g}13{r}. Show current process info (PID/PPID/UID)

{white}── Security ─────────────────────────────────────────────────────{reset}
 {g}14{r}. View audit log
 {g}15{r}. Setup / Enable 2FA
 {g}16{r}. Setup Decoy Password
  {g}0{r}. Logout
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def clear():
    os.system("cls" if sys.platform == "win32" else "clear")


def print_ok(msg):
    print(f"\n  {GREEN}✓{RESET} {msg}\n")


def print_err(msg):
    print(f"\n  {RED}✗{RESET} {msg}\n")


def print_info(msg):
    print(f"  {CYAN}ℹ{RESET} {msg}")


def pause():
    input(f"\n  {DIM}[Press Enter to continue...]{RESET}")


def pick_file_menu(username: str) -> str | None:
    """Show file list and let user pick one. Returns vault_filename or None."""
    files = filesystem.list_files(username)
    if not files:
        print_err("You have no files in the vault.")
        return None

    print(f"\n  {WHITE}Your vault files:{RESET}")
    for i, f in enumerate(files, 1):
        owner_tag = f"{GREEN}[owner]{RESET}" if f["is_owner"] else f"{CYAN}[shared]{RESET}"
        print(f"    {YELLOW}{i:2}{RESET}. {owner_tag} {f['original_name']:<40} {DIM}{f['size_bytes']} bytes  inode={f['inode']}{RESET}")

    choice = input("\n  Select file number (or 0 to cancel): ").strip()
    if choice == "0" or not choice.isdigit():
        return None
    idx = int(choice) - 1
    if 0 <= idx < len(files):
        return files[idx]["vault_filename"]
    print_err("Invalid selection.")
    return None


# ── Handlers ──────────────────────────────────────────────────────────────────

def handle_register():
    print(f"\n{WHITE}── Register New User ──────────────────────────────────────────{RESET}")
    username = input("  Username: ").strip()
    password = getpass.getpass("  Password (hidden): ")
    confirm  = getpass.getpass("  Confirm password: ")
    if password != confirm:
        print_err("Passwords do not match.")
        del password, confirm
        return
    ok, msg = auth.register(username, password)
    del password, confirm
    if ok:
        print_ok(msg)
        audit_log.log(username, "REGISTER", "-", "OK")
        print_info(f"shadow.db permissions: {oct(0o600)}  (OS chmod — owner only)")
    else:
        print_err(msg)
        audit_log.log(username, "REGISTER", "-", "FAIL", msg)


def handle_login() -> bool:
    print(f"\n{WHITE}── Login ───────────────────────────────────────────────────────{RESET}")
    username = input("  Username: ").strip()
    password = getpass.getpass("  Password (hidden): ")

    # First attempt without TOTP
    ok, msg = auth.login(username, password)

    if not ok and msg == "2FA_REQUIRED":
        print_info("2FA is enabled on this account.")
        totp_token = input("  Enter your 6-digit authenticator code: ").strip()
        ok, msg = auth.login(username, password, totp_token)

    if ok:
        print_ok(msg)
        audit_log.log(username, "LOGIN", "-", "OK", f"pid={os.getpid()}")
    else:
        print_err(msg)
        audit_log.log(username, "LOGIN_FAIL", "-", "FAIL", msg)
    del password
    return ok


def handle_upload(username: str):
    print(f"\n{WHITE}── Upload & Encrypt File ───────────────────────────────────────{RESET}")
    filepath = input("  Full path to file: ").strip().strip('"')

    if not os.path.isfile(filepath):
        print_err(f"File not found: {filepath}")
        return

    # Check size (buffer overflow / DOS prevention)
    file_stat = os.stat(filepath)
    size_mb = file_stat.st_size / (1024 * 1024)
    if size_mb > 100:
        print_err(f"File too large ({size_mb:.1f} MB). Max 100 MB.")
        audit_log.log(username, "UPLOAD_REJECT", filepath, "FAIL", "file too large")
        return

    print_info(f"File size: {file_stat.st_size} bytes  (inode={file_stat.st_ino})")

    # Step 1: Malware scan in child process
    print(f"\n  {YELLOW}→ Launching malware scanner in child process...{RESET}")
    scan_result = process_mgmt.scan_file_in_subprocess(filepath)
    print_info(f"  Scanner PID={scan_result.get('child_pid', '?')} | Parent PID={scan_result.get('parent_pid', '?')}")
    print_info(f"  Verdict: {scan_result.get('verdict', '?')} | Bytes scanned: {scan_result.get('bytes_scanned', '?')}")

    if scan_result.get("verdict") == "THREAT_DETECTED":
        print_err(f"MALWARE DETECTED: {scan_result.get('threats_found')}")
        audit_log.log(username, "UPLOAD_BLOCKED", filepath, "THREAT", str(scan_result.get("threats_found")))
        return

    # Step 2: Encrypt using password
    enc_password = getpass.getpass("  Encryption password (for this file): ")
    original_name = os.path.basename(filepath)

    print(f"\n  {YELLOW}→ Encrypting with AES-256-GCM...{RESET}")
    print_info("IV generated from os.urandom(12) — OS kernel CSPRNG")

    # Read raw bytes via OS file descriptor
    fd = os.open(filepath, os.O_RDONLY)
    try:
        plaintext = os.read(fd, file_stat.st_size)
    finally:
        os.close(fd)

    encrypted_payload = encryption.encrypt_data(plaintext, enc_password)
    del plaintext, enc_password

    # Step 3: Store in vault (O_EXCL for TOCTOU safety)
    vault_filename = filesystem.store_file(username, original_name, encrypted_payload)

    print_ok(f"File encrypted and stored: {vault_filename}")
    print_info(f"Vault location: data/vault/{vault_filename}")
    print_info(f"Permissions set to 0o600 (owner read/write only)")
    audit_log.log(username, "UPLOAD_ENCRYPT", original_name, "OK", vault_filename)

    delete_choice = input(f"\n  {YELLOW}Securely delete original unencrypted file? (y/N): {RESET}").strip().lower()
    if delete_choice in ('y', 'yes'):
        try:
            os.unlink(filepath)
            print_ok(f"Original file successfully removed from disk via os.unlink()")
            audit_log.log(username, "UPLOAD_DELETE_SOURCE", original_name, "OK", filepath)
        except OSError as e:
            print_err(f"Failed to delete original file: {e}")


def handle_list(username: str):
    print(f"\n{WHITE}── Your Vault Files ────────────────────────────────────────────{RESET}")
    files = filesystem.list_files(username)
    if not files:
        print_info("Vault is empty. Upload a file to get started.")
        return

    print(f"\n  {'#':<4} {'Name':<35} {'Owner':<15} {'Size':>8}  {'Inode':>10}  {'Perms':<10}  {'Modified':<20}")
    print(f"  {DIM}{'─'*110}{RESET}")
    for i, f in enumerate(files, 1):
        owner_tag = f"{GREEN}(you){RESET}" if f["is_owner"] else f"{CYAN}(shared){RESET}"
        display_owner = f['owner'].replace("_decoy", "")
        print(f"  {YELLOW}{i:<4}{RESET} {f['original_name']:<35} {display_owner:<15} {f['size_bytes']:>8}B  {f['inode']:>10}  {f['permissions']:<10}  {f['modified']:<20} {owner_tag}")


def handle_download(username: str):
    print(f"\n{WHITE}── Download & Decrypt File ─────────────────────────────────────{RESET}")
    vault_filename = pick_file_menu(username)
    if not vault_filename:
        return

    # Check access
    ok, msg = permissions.check_access(vault_filename, username, "read")
    if not ok:
        print_err(msg)
        audit_log.log(username, "DOWNLOAD_DENY", vault_filename, "FAIL", msg)
        return

    dest = input("  Save decrypted file to path: ").strip().strip('"')
    if not dest:
        return

    meta = filesystem._load_meta(vault_filename)
    is_owner = meta.get("owner") == username
    session = auth.get_session()

    if os.path.isdir(dest):
        dest = os.path.join(dest, meta.get("original_name", "decrypted_file"))

    encrypted_payload, err = filesystem.read_file(vault_filename, username)
    if err:
        print_err(err)
        return

    if is_owner:
        enc_password = getpass.getpass("  Decryption password: ")
        try:
            plaintext = encryption.decrypt_data(encrypted_payload, enc_password)
            del encrypted_payload, enc_password
        except ValueError as e:
            print_err(str(e))
            audit_log.log(username, "DOWNLOAD_FAIL", vault_filename, "FAIL", "wrong password")
            return
    else:
        # PKI Decryption flow
        shared_keys = meta.get("shared_keys", {})
        shared_key_hex = shared_keys.get(username)
        if not shared_key_hex:
            print_err("No PKI shared key found for this file. Ask the owner to share it again.")
            return
            
        private_key_obj = session.get("private_key")
        if not private_key_obj:
            print_err("Your RSA private key is not loaded in memory (decoy session?).")
            return
            
        try:
            encrypted_aes_key = bytes.fromhex(shared_key_hex)
            plaintext = encryption.decrypt_data_pki(encrypted_payload, private_key_obj, encrypted_aes_key)
            del encrypted_payload
        except Exception as e:
            print_err(f"PKI Decryption failed: {e}")
            audit_log.log(username, "DOWNLOAD_FAIL", vault_filename, "FAIL", "PKI error")
            return

    # Write decrypted file using OS fd
    try:
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    except OSError as e:
        print_err(f"Failed to save file: {e}")
        del plaintext
        return
        
    try:
        os.write(fd, plaintext)
    finally:
        os.close(fd)

    plaintext_len = len(plaintext)
    del plaintext

    print_ok(f"Decrypted file saved to: {dest}")
    print_info(f"File size: {plaintext_len} bytes")
    audit_log.log(username, "DOWNLOAD_DECRYPT", vault_filename, "OK", dest)


def handle_delete(username: str):
    print(f"\n{WHITE}── Delete File ─────────────────────────────────────────────────{RESET}")
    vault_filename = pick_file_menu(username)
    if not vault_filename:
        return

    confirm = input(f"  {RED}Are you sure you want to delete this file? (yes/no): {RESET}").strip().lower()
    if confirm != "yes":
        print_info("Cancelled.")
        return

    ok, msg = filesystem.delete_file(vault_filename, username)
    if ok:
        print_ok(msg)
        audit_log.log(username, "DELETE", vault_filename, "OK")
    else:
        print_err(msg)
        audit_log.log(username, "DELETE_FAIL", vault_filename, "FAIL", msg)


def handle_view_permissions(username: str):
    print(f"\n{WHITE}── View File Permissions ───────────────────────────────────────{RESET}")
    vault_filename = pick_file_menu(username)
    if not vault_filename:
        return

    perm_info = permissions.get_permissions(vault_filename)
    if not perm_info:
        print_err("Could not read permissions.")
        return

    print(f"\n  File:          {perm_info['file']}")
    print(f"  Original name: {perm_info['original_name']}")
    print(f"  Owner:         {perm_info['owner']}")
    print(f"  Shared with:   {', '.join(perm_info['shared_with']) or '(nobody)'}")
    print(f"  Raw mode:      {YELLOW}{perm_info['raw_mode']}{RESET}  (chmod-style octal)")
    print(f"  Inode:         {perm_info['inode']}")
    print(f"\n  {WHITE}Permission Bits (stat.S_I* constants):{RESET}")
    for bit_name, value in perm_info["permissions_table"].items():
        color = GREEN if value == "✓" else RED
        print(f"    {bit_name:<18} {color}{value}{RESET}")

    audit_log.log(username, "VIEW_PERMISSIONS", vault_filename, "OK")


def handle_chmod(username: str):
    print(f"\n{WHITE}── chmod — Change File Permissions ─────────────────────────────{RESET}")
    vault_filename = pick_file_menu(username)
    if not vault_filename:
        return

    print(f"  {DIM}Common modes: 0o600 (owner rw), 0o644 (owner rw, others r), 0o400 (read-only){RESET}")
    mode_str = input("  Enter new mode in octal (e.g. 0o600 or 600): ").strip()

    try:
        if mode_str.startswith("0o") or mode_str.startswith("0O"):
            mode = int(mode_str, 8)
        elif mode_str.isdigit() and len(mode_str) <= 4:
            mode = int(mode_str, 8)
        else:
            mode = int(mode_str, 0)
    except ValueError:
        print_err("Invalid octal mode.")
        return

    ok, msg = permissions.chmod_file(vault_filename, username, mode)
    if ok:
        print_ok(msg)
        audit_log.log(username, "CHMOD", vault_filename, "OK", oct(mode))
    else:
        print_err(msg)
        audit_log.log(username, "CHMOD_FAIL", vault_filename, "FAIL", msg)


def handle_share(username: str):
    print(f"\n{WHITE}── Share File ──────────────────────────────────────────────────{RESET}")
    vault_filename = pick_file_menu(username)
    if not vault_filename:
        return

    target = input("  Share with username: ").strip()
    enc_password = getpass.getpass("  File encryption password: ")
    ok, msg = sharing.share_file(vault_filename, username, target, enc_password)
    del enc_password
    if ok:
        print_ok(msg)
    else:
        print_err(msg)


def handle_revoke(username: str):
    print(f"\n{WHITE}── Revoke Shared Access ────────────────────────────────────────{RESET}")
    vault_filename = pick_file_menu(username)
    if not vault_filename:
        return

    target = input("  Revoke access for username: ").strip()
    ok, msg = sharing.unshare_file(vault_filename, username, target)
    if ok:
        print_ok(msg)
    else:
        print_err(msg)


def handle_stat(username: str):
    print(f"\n{WHITE}── File stat() — OS Kernel Inode Data ──────────────────────────{RESET}")
    vault_filename = pick_file_menu(username)
    if not vault_filename:
        return

    stat_data = filesystem.get_file_stat(vault_filename)
    if not stat_data:
        print_err("File not found.")
        return

    print(f"\n  {WHITE}Raw stat(2) structure from the kernel:{RESET}")
    for k, v in stat_data.items():
        print(f"    {CYAN}{k:<12}{RESET} = {v}")

    audit_log.log(username, "STAT", vault_filename, "OK")


def handle_malware_scan(username: str):
    print(f"\n{WHITE}── Malware Scan in Child Process ───────────────────────────────{RESET}")
    filepath = input("  Path to file to scan: ").strip().strip('"')

    if not os.path.isfile(filepath):
        print_err("File not found.")
        return

    print(f"\n  {YELLOW}→ Spawning child process (fork+exec / CreateProcess)...{RESET}")
    result = process_mgmt.scan_file_in_subprocess(filepath)

    print(f"\n  {WHITE}Scan Results:{RESET}")
    print(f"    Parent PID:    {result.get('parent_pid', '?')}")
    print(f"    Scanner PID:   {result.get('child_pid', result.get('scanner_pid', '?'))}")
    print(f"    Bytes scanned: {result.get('bytes_scanned', '?')}")

    verdict = result.get("verdict", "UNKNOWN")
    if verdict == "CLEAN":
        print(f"    Verdict:       {GREEN}✓ CLEAN{RESET}")
    elif verdict == "THREAT_DETECTED":
        print(f"    Verdict:       {RED}✗ THREAT DETECTED{RESET}")
        for t in result.get("threats_found", []):
            print(f"      {RED}→ {t}{RESET}")
    else:
        print(f"    Verdict:       {YELLOW}{verdict}{RESET}")
        if "error" in result:
            print(f"    Error: {result['error']}")

    audit_log.log(username, "MALWARE_SCAN", filepath, verdict)


def handle_process_info():
    print(f"\n{WHITE}── Current Process Info (OS Kernel Data) ───────────────────────{RESET}")
    info = process_mgmt.get_process_info()
    print(f"\n  {WHITE}Process Table Entry:{RESET}")
    for k, v in info.items():
        print(f"    {CYAN}{k:<10}{RESET} = {v}")

    print(f"\n  {WHITE}Active Python Processes (from OS):{RESET}")
    procs = process_mgmt.list_active_processes()
    for line in procs[:10]:
        print(f"    {DIM}{line}{RESET}")


def handle_audit_log():
    print(f"\n{WHITE}── Audit Log (append-only O_APPEND writes) ─────────────────────{RESET}")
    entries = audit_log.read_log()
    if not entries:
        print_info("Audit log is empty.")
        return
    print(f"\n  Showing last {min(30, len(entries))} entries:\n")
    for entry in entries[-30:]:
        if "FAIL" in entry or "DENY" in entry or "THREAT" in entry:
            print(f"  {RED}{entry}{RESET}")
        elif "OK" in entry:
            print(f"  {GREEN}{entry}{RESET}")
        else:
            print(f"  {DIM}{entry}{RESET}")


def handle_setup_2fa(username: str):
    print(f"\n{WHITE}── Two-Factor Authentication Setup ─────────────────────────────{RESET}")
    print_info("This will generate a TOTP secret using os.urandom() (OS kernel entropy)")

    ok, secret, uri = auth.setup_2fa(username)
    if not ok:
        print_err("Failed to set up 2FA.")
        return

    print(f"\n  {YELLOW}Your 2FA Secret:{RESET} {WHITE}{secret}{RESET}")
    print(f"  {DIM}Scan this URI in your authenticator app:{RESET}")
    print(f"  {DIM}{uri}{RESET}")
    print(f"\n  Add this secret to Google Authenticator, Authy, or any TOTP app.")

    token = input("\n  Enter the 6-digit code from your app to verify & enable: ").strip()
    ok, msg = auth.enable_2fa(username, token)
    if ok:
        print_ok(msg)
        audit_log.log(username, "ENABLE_2FA", "-", "OK")
    else:
        print_err(msg)
        audit_log.log(username, "ENABLE_2FA_FAIL", "-", "FAIL")


def handle_setup_decoy(username: str, is_decoy: bool):
    print(f"\n{WHITE}── Setup Decoy Password ────────────────────────────────────────{RESET}")
    if is_decoy:
        print_err("Cannot setup a decoy password while logged into a decoy session.")
        return
        
    print_info("A decoy password creates a separate, hidden vault. If forced to provide a password,")
    print_info("you can provide the decoy password to reveal plausible but unclassified files.")
    decoy_pass = getpass.getpass("  Enter new Decoy Password: ")
    confirm_pass = getpass.getpass("  Confirm Decoy Password: ")
    
    if decoy_pass != confirm_pass:
        print_err("Passwords do not match.")
        del decoy_pass, confirm_pass
        return
        
    ok, msg = auth.setup_decoy(username, decoy_pass)
    del decoy_pass, confirm_pass
    if ok:
        print_ok(msg)
        audit_log.log(username, "SETUP_DECOY", "-", "OK")
    else:
        print_err(msg)


# ── Main Loop ─────────────────────────────────────────────────────────────────

def main():
    print(BANNER)
    session = None

    while True:
        session = auth.get_session()
        username = session["username"] if session else None
        effective_user = session["effective_user"] if session else None
        is_decoy = session.get("is_decoy", False) if session else False

        if not session:
            print(LOGGED_OUT_MENU)
            choice = input(f"  {WHITE}>{RESET} ").strip()

            if choice == "1":
                handle_register()
            elif choice == "2":
                handle_login()
            elif choice == "0":
                print(f"\n  {CYAN}Goodbye. All session data cleared from memory.{RESET}\n")
                sys.exit(0)
            else:
                print_err("Invalid option.")

        else:
            menu = LOGGED_IN_MENU_TEMPLATE.format(
                cyan=CYAN, reset=RESET, white=WHITE, g=GREEN, r=RESET,
                user=f"{WHITE}{username}{RESET}",
                pid=os.getpid()
            )
            print(menu)
            choice = input(f"  {WHITE}>{RESET} ").strip()

            if   choice == "3":  handle_upload(effective_user)
            elif choice == "4":  handle_list(effective_user)
            elif choice == "5":  handle_download(effective_user)
            elif choice == "6":  handle_delete(effective_user)
            elif choice == "7":  handle_view_permissions(effective_user)
            elif choice == "8":  handle_chmod(effective_user)
            elif choice == "9":  handle_share(effective_user)
            elif choice == "10": handle_revoke(effective_user)
            elif choice == "11": handle_stat(effective_user)
            elif choice == "12": handle_malware_scan(effective_user)
            elif choice == "13": handle_process_info()
            elif choice == "14": handle_audit_log()
            elif choice == "15": handle_setup_2fa(username)
            elif choice == "16": handle_setup_decoy(username, is_decoy)
            elif choice == "0":
                auth.logout()
                audit_log.log(effective_user, "LOGOUT", "-", "OK")
                print_ok("Logged out. Session cleared from memory.")
            else:
                print_err("Invalid option.")

        pause()


if __name__ == "__main__":
    main()
