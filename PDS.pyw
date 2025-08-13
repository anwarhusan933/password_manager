import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import os
import base64
import hashlib
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyperclip
import secrets
import string

DATA_FILE = "passwords.enc.jsonl"   # JSON Lines (one JSON object per line)
MASTER_FILE = "master.hash"

class PasswordManager:
    # --- Password Strength Meter ---
    def create_strength_bar(self, parent):
        frame = ttk.Frame(parent)
        canvas = tk.Canvas(frame, width=180, height=12, bg=parent.cget('background'), highlightthickness=0)
        canvas.pack(side=tk.LEFT, padx=5)
        label = ttk.Label(frame, text="", font=('Arial', 9))
        label.pack(side=tk.LEFT, padx=5)
        return frame, canvas, label

    def update_strength_bar(self, password, canvas, label):
        score = 0
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if any(c.isupper() for c in password):
            score += 1
        if any(c.islower() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in string.punctuation for c in password):
            score += 1
        # Draw bar
        canvas.delete('all')
        colors = ['#e74c3c', '#e67e22', '#f1c40f', '#2ecc71', '#27ae60', '#1abc9c']
        width = 180 * min(score, 6) / 6
        color = colors[min(score, 5)]
        canvas.create_rectangle(0, 0, width, 12, fill=color, outline=color)
        if score < 3:
            label.config(text="Weak", foreground='#e74c3c')
        elif score < 5:
            label.config(text="Medium", foreground='#f1c40f')
        else:
            label.config(text="Strong", foreground='#27ae60')
    # ---------- UI SETUP ----------
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("900x650")

        # Security parameters
        self.salt = b'salt_'          # TODO: make per-user unique salt and store it
        self.iterations = 200_000     # a bit higher KDF iterations
        self.master_password_hash = None
        self.fernet_key = None
        self.current_edit = None

        # File paths
        self.data_file = DATA_FILE
        self.master_file = MASTER_FILE

        self.nav_btns = []  # keep references to sidebar buttons so we can disable/enable

        self.configure_styles()
        self.setup_ui()
        self.check_first_run()

    def configure_styles(self):
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except Exception:
            pass

        self.root.configure(bg='#0a1f3a')
        style.configure('TFrame', background='#0a1f3a')
        style.configure('TLabel', background='#0a1f3a', foreground='white', font=('Arial', 10))
        style.configure('TButton', font=('Arial', 10))
        style.map('TButton', relief=[('pressed', 'sunken'), ('!pressed', 'raised')])
        style.configure('TEntry', fieldbackground='white', foreground='black', font=('Arial', 11))
        style.configure('Treeview', background='white', fieldbackground='white', foreground='black')
        style.configure('Treeview.Heading', font=('Arial', 10, 'bold'))

    def setup_ui(self):
        # Main container with sidebar and content
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Sidebar for navigation
        self.sidebar = ttk.Frame(self.main_frame, width=200)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(10,0), pady=10)
        self.sidebar.pack_propagate(False)

        nav_label = ttk.Label(self.sidebar, text="MENU", font=('Arial', 13, 'bold'))
        nav_label.pack(pady=(10, 20))

        nav_items = [
            ("🏠 Home", self.show_menu, "Go to main menu"),
            ("➕ Add Entry", self.show_add_form, "Add a new password entry"),
            ("📋 All Entries", self.show_all_entries, "View all saved entries"),
            ("🔍 Search", self.show_search, "Search your entries"),
            ("🔑 Generate", self.generate_password, "Generate a strong password"),
            ("🚪 Logout", self.logout, "Logout and lock app"),
        ]
        for text, command, tip in nav_items:
            btn = ttk.Button(self.sidebar, text=text, command=command)
            btn.pack(fill=tk.X, pady=6, ipady=6, padx=10)
            btn.bind("<Enter>", lambda e, t=tip: self.show_status(t))
            btn.bind("<Leave>", lambda e: self.clear_status())
            self.nav_btns.append(btn)

        # Main content area
        self.content_frame = ttk.Frame(self.main_frame)
        self.content_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Status bar (use tk.Label to allow background)
        self.status_var = tk.StringVar()
        self.status_bar = tk.Label(self.root, textvariable=self.status_var, anchor='w',
                                   bg='#222', fg='white', font=('Arial', 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Login screen
        self.login_frame = ttk.Frame(self.content_frame)
        ttk.Label(self.login_frame, text="🔒 Secure Password Manager", font=('Arial', 18, 'bold')).pack(pady=30)
        ttk.Label(self.login_frame, text="Master Password:").pack(pady=8)
        self.master_pw_entry = ttk.Entry(self.login_frame, show="•", font=('Arial', 12))
        self.master_pw_entry.pack(pady=8, ipadx=60)
        self.master_pw_entry.bind('<Return>', lambda e: self.handle_login())
        # Strength bar for master password
        self.master_pw_strength_frame, self.master_pw_strength_canvas, self.master_pw_strength_label = self.create_strength_bar(self.login_frame)
        self.master_pw_strength_frame.pack(pady=2)
        self.master_pw_entry.bind('<KeyRelease>', self.update_master_pw_strength)
        self.login_button = ttk.Button(self.login_frame, text="Login", command=self.handle_login)
        self.login_button.pack(pady=18, ipadx=10, ipady=4)

    def update_master_pw_strength(self, event=None):
        password = self.master_pw_entry.get()
        self.update_strength_bar(password, self.master_pw_strength_canvas, self.master_pw_strength_label)

        # Main menu screen
        self.menu_frame = ttk.Frame(self.content_frame)
        ttk.Label(self.menu_frame, text="Welcome to Password Manager", font=('Arial', 17, 'bold')).pack(pady=30)
        ttk.Label(self.menu_frame, text="Select an option from the menu on the left.", font=('Arial', 12)).pack(pady=10)

        # Add entry form
        self.add_frame = ttk.Frame(self.content_frame)
        ttk.Label(self.add_frame, text="Add New Entry", font=('Arial', 15, 'bold')).pack(pady=15)
        form_frame = ttk.Frame(self.add_frame)
        form_frame.pack(pady=10)
        fields = [
            ("Service/Website:", 'service'),
            ("Username/Email:", 'username'),
            ("Password:", 'password'),
            ("Description:", 'description'),
        ]
        self.entry_vars = {}
        for i, (label, name) in enumerate(fields):
            ttk.Label(form_frame, text=label).grid(row=i, column=0, sticky='e', padx=7, pady=7)
            entry = ttk.Entry(form_frame, font=('Arial', 11)) if name != 'password' else ttk.Entry(form_frame, show="•", font=('Arial', 11))
            entry.grid(row=i, column=1, padx=7, pady=7, ipadx=60)
            self.entry_vars[name] = entry
            if name == 'password':
                # Strength bar for password field
                self.pw_strength_frame, self.pw_strength_canvas, self.pw_strength_label = self.create_strength_bar(form_frame)
                self.pw_strength_frame.grid(row=i+1, column=1, sticky='w', pady=(0,7))
                entry.bind('<KeyRelease>', self.update_entry_pw_strength)
                # Eye / Generate / Copy buttons
                ttk.Button(form_frame, text="👁", width=2, command=self.toggle_password_visibility)\
                    .grid(row=i, column=2, padx=3)
                gen_btn = ttk.Button(form_frame, text="🔑", width=2, command=self.generate_password_for_entry)
                gen_btn.grid(row=i, column=3, padx=3)
                copy_btn = ttk.Button(form_frame, text="📋", width=2, command=self.copy_password_to_clipboard)
                copy_btn.grid(row=i, column=4, padx=3)

    def update_entry_pw_strength(self, event=None):
        password = self.entry_vars['password'].get()
        self.update_strength_bar(password, self.pw_strength_canvas, self.pw_strength_label)

        button_frame = ttk.Frame(self.add_frame)
        button_frame.pack(pady=12)
        self.save_button = ttk.Button(button_frame, text="💾 Save", command=self.save_entry)
        self.save_button.pack(side=tk.LEFT, padx=7, ipadx=8, ipady=3)
        cancel_btn = ttk.Button(button_frame, text="Cancel", command=self.show_menu)
        cancel_btn.pack(side=tk.LEFT, padx=7, ipadx=8, ipady=3)

        # All entries
        self.entries_frame = ttk.Frame(self.content_frame)
        ttk.Label(self.entries_frame, text="All Entries", font=('Arial', 15, 'bold')).pack(pady=15)
        self.tree = ttk.Treeview(self.entries_frame, columns=('Service', 'Username', 'Description'), show='headings')
        for col, text in zip(('Service', 'Username', 'Description'),
                             ('Service/Website', 'Username/Email', 'Description')):
            self.tree.heading(col, text=text)
            self.tree.column(col, width=220 if col != 'Description' else 300, stretch=True)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.tree.bind('<Double-1>', self.on_entry_double_click)

        ef_btns = ttk.Frame(self.entries_frame)
        ef_btns.pack(pady=10)
        ttk.Button(ef_btns, text="⬅ Back", command=self.show_menu).pack(side=tk.LEFT, padx=7, ipadx=8, ipady=3)
        ttk.Button(ef_btns, text="🔄 Refresh", command=self.load_entries).pack(side=tk.LEFT, padx=7, ipadx=8, ipady=3)

        # Search
        self.search_frame = ttk.Frame(self.content_frame)
        ttk.Label(self.search_frame, text="Search Entries", font=('Arial', 15, 'bold')).pack(pady=15)
        search_box = ttk.Frame(self.search_frame)
        search_box.pack(pady=10)
        ttk.Label(search_box, text="Search:").pack(side=tk.LEFT)
        self.search_entry = ttk.Entry(search_box, font=('Arial', 11))
        self.search_entry.pack(side=tk.LEFT, padx=5, ipadx=100)
        self.search_entry.bind('<Return>', lambda e: self.perform_search())
        ttk.Button(search_box, text="🔍", command=self.perform_search).pack(side=tk.LEFT, padx=5)

        self.search_results = ttk.Treeview(self.search_frame, columns=('Service', 'Username', 'Description'), show='headings')
        for col, text in zip(('Service', 'Username', 'Description'),
                             ('Service/Website', 'Username/Email', 'Description')):
            self.search_results.heading(col, text=text)
            self.search_results.column(col, width=220 if col != 'Description' else 300, stretch=True)
        self.search_results.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.search_results.bind('<Double-1>', self.on_search_result_double_click)

        sf_btns = ttk.Frame(self.search_frame)
        sf_btns.pack(pady=10)
        ttk.Button(sf_btns, text="⬅ Back", command=self.show_menu).pack(side=tk.LEFT, padx=7, ipadx=8, ipady=3)

        # Start at login and lock the UI
        self.set_locked_ui(True)
        self.show_login()

    # ---------- STATUS ----------
    def show_status(self, msg): self.status_var.set(msg)
    def clear_status(self): self.status_var.set("")

    def set_locked_ui(self, locked: bool):
        state = tk.DISABLED if locked else tk.NORMAL
        for btn in self.nav_btns:
            # Allow Home and Logout even when locked; disable others
            if btn.cget('text').startswith('🏠') or btn.cget('text').startswith('🚪'):
                btn.configure(state=tk.NORMAL)
            else:
                btn.configure(state=state)

    # ---------- FIRST RUN / AUTH ----------
    def check_password_strength(self, event=None):
        password = self.master_pw_entry.get()
        if not password:
            self.strength_label.config(text="")
            return
        strength = 0
        strength += 1 if len(password) >= 8 else 0
        strength += 1 if len(password) >= 12 else 0
        strength += 1 if any(c.isupper() for c in password) else 0
        strength += 1 if any(c.islower() for c in password) else 0
        strength += 1 if any(c.isdigit() for c in password) else 0
        strength += 1 if any(c in string.punctuation for c in password) else 0
        if strength < 3:
            self.strength_label.config(text="Weak", foreground='red')
        elif strength < 5:
            self.strength_label.config(text="Medium", foreground='orange')
        else:
            self.strength_label.config(text="Strong", foreground='green')

    def check_first_run(self):
        if not os.path.exists(self.master_file):
            response = messagebox.askyesno("First Run", "No master password found. Set one now?")
            if response:
                self.setup_master_password()
            else:
                self.root.quit()

    def setup_master_password(self):
        password = simpledialog.askstring("Set Master Password", "Enter a new master password:", show='*')
        if not password:
            messagebox.showerror("Error", "Master password cannot be empty")
            return self.check_first_run()
        if len(password) < 8:
            messagebox.showwarning("Weak Password", "Use at least 8 characters.")
            return self.setup_master_password()
        confirm = simpledialog.askstring("Confirm Master Password", "Confirm your master password:", show='*')
        if password != confirm:
            messagebox.showerror("Error", "Passwords don't match")
            return self.setup_master_password()

        self.master_password_hash = self.hash_password(password)
        with open(self.master_file, 'wb') as f:
            f.write(self.master_password_hash)

        # Directly unlock the vault after setting the password
        self.fernet_key = self.derive_key(password)
        self.set_locked_ui(False)
        messagebox.showinfo("Success", "Master password set and vault unlocked")
        self.show_menu()
        self.load_entries()

    def hash_password(self, password: str) -> bytes:
        return hashlib.sha256(password.encode()).digest()

    def derive_key(self, password: str) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=self.salt, iterations=self.iterations)
        key = kdf.derive(password.encode())
        return base64.urlsafe_b64encode(key)

    def handle_login(self):
        password = self.master_pw_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        try:
            with open(self.master_file, 'rb') as f:
                stored_hash = f.read()
            if self.hash_password(password) == stored_hash:
                self.fernet_key = self.derive_key(password)
                self.master_pw_entry.delete(0, tk.END)
                self.set_locked_ui(False)
                self.show_menu()
                self.load_entries()
            else:
                messagebox.showerror("Error", "Incorrect master password")
        except FileNotFoundError:
            messagebox.showerror("Error", "Master password not set. Please set it first.")
            self.setup_master_password()

    # ---------- NAV ----------
    def show_login(self):
        self.hide_all_frames()
        self.login_frame.pack(fill=tk.BOTH, expand=True)

    def show_menu(self):
        self.hide_all_frames()
        self.menu_frame.pack(fill=tk.BOTH, expand=True)

    def show_add_form(self):
        if not self._ensure_key():
            return
        self.hide_all_frames()
        for entry in self.entry_vars.values():
            entry.delete(0, tk.END)
        self.add_frame.pack(fill=tk.BOTH, expand=True)
        self.save_button.config(text="Save", command=self.save_entry)
        self.current_edit = None

    def show_all_entries(self):
        if not self._ensure_key():
            return
        self.hide_all_frames()
        self.entries_frame.pack(fill=tk.BOTH, expand=True)
        self.load_entries()

    def show_search(self):
        if not self._ensure_key():
            return
        self.hide_all_frames()
        self.search_frame.pack(fill=tk.BOTH, expand=True)
        self.search_entry.delete(0, tk.END)
        for item in self.search_results.get_children():
            self.search_results.delete(item)

    def hide_all_frames(self):
        for frame in [self.login_frame, self.menu_frame, self.add_frame, self.entries_frame, self.search_frame]:
            frame.pack_forget()

    # ---------- CRYPTO HELPERS ----------
    def _ensure_key(self):
        if not self.fernet_key:
            messagebox.showerror("Locked", "Vault is locked. Please log in to continue.")
            self.set_locked_ui(True)
            self.show_login()
            return False
        return True

    def encrypt_data(self, data: str) -> str:
        if not self._ensure_key():
            raise ValueError("Vault locked")
        fernet = Fernet(self.fernet_key)
        return fernet.encrypt(data.encode()).decode()

    def decrypt_data(self, encrypted_data: str) -> str:
        if not self._ensure_key():
            raise ValueError("Vault locked")
        fernet = Fernet(self.fernet_key)
        return fernet.decrypt(encrypted_data.encode()).decode()

    # ---------- STORAGE (JSONL) ----------
    def _read_entries_jsonl(self):
        if not os.path.exists(self.data_file):
            return []
        entries = []
        with open(self.data_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    # skip corrupted line
                    continue
        return entries

    def _write_entries_jsonl(self, entries):
        with open(self.data_file, 'w', encoding='utf-8') as f:
            for obj in entries:
                f.write(json.dumps(obj, ensure_ascii=False) + '\n')

    # ---------- CRUD ----------
    def save_entry(self):
        if not self._ensure_key():
            return
        entry_data = {
            'service': self.entry_vars['service'].get().strip(),
            'username': self.entry_vars['username'].get().strip(),
            'password': self.entry_vars['password'].get(),
            'description': self.entry_vars['description'].get().strip(),
        }
        if not entry_data['service'] or not entry_data['username'] or not entry_data['password']:
            messagebox.showerror("Error", "Service, Username and Password are required")
            return

        try:
            encrypted_entry = {k: self.encrypt_data(v) for k, v in entry_data.items()}
        except Exception:
            return  # _ensure_key already showed an error

        entries = self._read_entries_jsonl()
        entries.append(encrypted_entry)
        try:
            self._write_entries_jsonl(entries)
            messagebox.showinfo("Success", "Entry saved successfully")
            self.show_menu()
        except Exception as e:
            messagebox.showerror("Error", f"Could not save entry\n{e!r}")

    def load_entries(self):
        if not self._ensure_key():
            return
        for item in self.tree.get_children():
            self.tree.delete(item)

        entries = self._read_entries_jsonl()
        for enc in entries:
            try:
                dec = {
                    'service': self.decrypt_data(enc['service']),
                    'username': self.decrypt_data(enc['username']),
                    'description': self.decrypt_data(enc.get('description', '')),
                }
                self.tree.insert('', tk.END, values=(dec['service'], dec['username'], dec['description']))
            except Exception:
                # skip if decrypt fails
                continue

    def perform_search(self):
        if not self._ensure_key():
            return
        query = self.search_entry.get().strip().lower()
        if not query:
            messagebox.showwarning("Warning", "Please enter a search term")
            return

        for item in self.search_results.get_children():
            self.search_results.delete(item)

        entries = self._read_entries_jsonl()
        found = False
        for enc in entries:
            try:
                dec = {
                    'service': self.decrypt_data(enc['service']),
                    'username': self.decrypt_data(enc['username']),
                    'password': self.decrypt_data(enc['password']),
                    'description': self.decrypt_data(enc.get('description', '')),
                }
                if (query in dec['service'].lower() or
                    query in dec['username'].lower() or
                    query in dec['description'].lower()):
                    self.search_results.insert('', tk.END, values=(dec['service'], dec['username'], dec['description']))
                    found = True
            except Exception:
                continue
        if not found:
            messagebox.showinfo("Info", "No matching entries found")

    def _selected_values(self, tree):
        sel = tree.selection()
        if not sel:
            return None
        return tree.item(sel[0], 'values')

    def on_entry_double_click(self, event):
        if not self._ensure_key():
            return
        values = self._selected_values(self.tree)
        if not values:
            return
        service, username = values[0], values[1]
        entry = self.find_entry(service, username)
        if entry:
            self.show_entry_details(entry)

    def on_search_result_double_click(self, event):
        if not self._ensure_key():
            return
        values = self._selected_values(self.search_results)
        if not values:
            return
        service, username = values[0], values[1]
        entry = self.find_entry(service, username)
        if entry:
            self.show_entry_details(entry)

    def find_entry(self, service, username):
        if not self._ensure_key():
            return None
        entries = self._read_entries_jsonl()
        for enc in entries:
            try:
                dec_service = self.decrypt_data(enc['service'])
                dec_username = self.decrypt_data(enc['username'])
                if dec_service == service and dec_username == username:
                    return {
                        'service': dec_service,
                        'username': dec_username,
                        'password': self.decrypt_data(enc['password']),
                        'description': self.decrypt_data(enc.get('description', '')),
                    }
            except Exception:
                continue
        return None

    def show_entry_details(self, entry):
        top = tk.Toplevel(self.root)
        top.title("Entry Details")
        top.geometry("420x320")

        ttk.Label(top, text="Entry Details", font=('Arial', 14, 'bold')).pack(pady=10)

        details_frame = ttk.Frame(top)
        details_frame.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)

        ttk.Label(details_frame, text="Service/Website:").grid(row=0, column=0, sticky='e', padx=5, pady=5)
        ttk.Label(details_frame, text=entry['service']).grid(row=0, column=1, sticky='w', padx=5, pady=5)

        ttk.Label(details_frame, text="Username/Email:").grid(row=1, column=0, sticky='e', padx=5, pady=5)
        ttk.Label(details_frame, text=entry['username']).grid(row=1, column=1, sticky='w', padx=5, pady=5)

        ttk.Label(details_frame, text="Password:").grid(row=2, column=0, sticky='e', padx=5, pady=5)
        pwd_frame = ttk.Frame(details_frame)
        pwd_frame.grid(row=2, column=1, sticky='w', padx=5, pady=5)
        password_label = ttk.Label(pwd_frame, text="••••••••")
        password_label.pack(side=tk.LEFT)

        def show_password():
            password_label.config(text=entry['password'])
            show_btn.config(text="Hide", command=hide_password)

        def hide_password():
            password_label.config(text="••••••••")
            show_btn.config(text="Show", command=show_password)

        show_btn = ttk.Button(pwd_frame, text="Show", command=show_password)
        show_btn.pack(side=tk.LEFT, padx=5)
        ttk.Button(pwd_frame, text="Copy", command=lambda: pyperclip.copy(entry['password'])).pack(side=tk.LEFT)

        ttk.Label(details_frame, text="Description:").grid(row=3, column=0, sticky='ne', padx=5, pady=5)
        ttk.Label(details_frame, text=entry['description'], wraplength=300).grid(row=3, column=1, sticky='nw', padx=5, pady=5)

        btns = ttk.Frame(top)
        btns.pack(pady=10)
        ttk.Button(btns, text="Edit", command=lambda: self.edit_entry(entry, top)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btns, text="Delete", command=lambda: self.delete_entry(entry, top)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btns, text="Close", command=top.destroy).pack(side=tk.LEFT, padx=5)

    def edit_entry(self, entry, top):
        top.destroy()
        if not self._ensure_key():
            return
        self.show_add_form()
        self.entry_vars['service'].insert(0, entry['service'])
        self.entry_vars['username'].insert(0, entry['username'])
        self.entry_vars['password'].insert(0, entry['password'])
        self.entry_vars['description'].insert(0, entry['description'])
        self.current_edit = entry
        self.save_button.config(text="Update", command=self.update_entry)

    def update_entry(self):
        if not self._ensure_key():
            return
        if not self.current_edit:
            messagebox.showerror("Error", "No entry selected for update")
            return

        updated_entry = {
            'service': self.entry_vars['service'].get().strip(),
            'username': self.entry_vars['username'].get().strip(),
            'password': self.entry_vars['password'].get(),
            'description': self.entry_vars['description'].get().strip(),
        }
        if not updated_entry['service'] or not updated_entry['username'] or not updated_entry['password']:
            messagebox.showerror("Error", "Service, Username and Password are required")
            return

        entries = self._read_entries_jsonl()
        updated = False
        for i, enc in enumerate(entries):
            try:
                dec_service = self.decrypt_data(enc['service'])
                dec_username = self.decrypt_data(enc['username'])
                if dec_service == self.current_edit['service'] and dec_username == self.current_edit['username']:
                    entries[i] = {k: self.encrypt_data(v) for k, v in updated_entry.items()}
                    updated = True
                    break
            except Exception:
                continue

        if not updated:
            messagebox.showerror("Error", "Entry not found for updating")
            return

        try:
            self._write_entries_jsonl(entries)
            messagebox.showinfo("Success", "Entry updated successfully")
            self.show_menu()
        except Exception as e:
            messagebox.showerror("Error", f"Could not update entry\n{e!r}")

    def delete_entry(self, entry, top):
        if not self._ensure_key():
            return
        if not messagebox.askyesno("Confirm", "Are you sure you want to delete this entry?"):
            return
        top.destroy()

        entries = self._read_entries_jsonl()
        filtered = []
        deleted = False
        for enc in entries:
            try:
                dec_service = self.decrypt_data(enc['service'])
                dec_username = self.decrypt_data(enc['username'])
                if dec_service == entry['service'] and dec_username == entry['username']:
                    deleted = True
                    continue
                filtered.append(enc)
            except Exception:
                # if decrypt fails, keep it to avoid accidental data loss
                filtered.append(enc)

        if not deleted:
            messagebox.showerror("Error", "Entry not found for deletion")
            return

        try:
            self._write_entries_jsonl(filtered)
            messagebox.showinfo("Success", "Entry deleted successfully")
            if hasattr(self, 'tree'):
                self.load_entries()
        except Exception as e:
            messagebox.showerror("Error", f"Could not delete entry\n{e!r}")

    # ---------- UTIL ----------
    def generate_password(self):
        def generate():
            length = length_var.get()
            if length < 8 or length > 50:
                messagebox.showerror("Error", "Password length must be between 8 and 50")
                return
            if not any([upper_var.get(), lower_var.get(), digits_var.get(), special_var.get()]):
                messagebox.showerror("Error", "Select at least one character type")
                return
            pool = ""
            if upper_var.get(): pool += string.ascii_uppercase
            if lower_var.get(): pool += string.ascii_lowercase
            if digits_var.get(): pool += string.digits
            if special_var.get(): pool += string.punctuation
            password_var.set(''.join(secrets.choice(pool) for _ in range(length)))

        def copy_to_clipboard():
            if password_var.get():
                pyperclip.copy(password_var.get())
                messagebox.showinfo("Copied", "Password copied to clipboard")

        top = tk.Toplevel(self.root)
        top.title("Password Generator")
        top.geometry("420x340")

        ttk.Label(top, text="Password Generator", font=('Arial', 14, 'bold')).pack(pady=10)
        options = ttk.Frame(top); options.pack(pady=10, padx=20)

        ttk.Label(options, text="Length:").grid(row=0, column=0, sticky='e', padx=5, pady=5)
        length_var = tk.IntVar(value=12)
        ttk.Spinbox(options, from_=8, to=50, textvariable=length_var, width=6).grid(row=0, column=1, sticky='w', padx=5, pady=5)

        ttk.Label(options, text="Character Types:").grid(row=1, column=0, sticky='ne', padx=5, pady=5)
        types = ttk.Frame(options); types.grid(row=1, column=1, sticky='w')
        upper_var = tk.BooleanVar(value=True)
        lower_var = tk.BooleanVar(value=True)
        digits_var = tk.BooleanVar(value=True)
        special_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(types, text="Uppercase (A-Z)", variable=upper_var).pack(anchor='w')
        ttk.Checkbutton(types, text="Lowercase (a-z)", variable=lower_var).pack(anchor='w')
        ttk.Checkbutton(types, text="Digits (0-9)", variable=digits_var).pack(anchor='w')
        ttk.Checkbutton(types, text="Special (!@#...)", variable=special_var).pack(anchor='w')

        password_var = tk.StringVar()
        ttk.Entry(top, textvariable=password_var, state='readonly', font=('Arial', 12)).pack(pady=10, ipadx=50)

        btns = ttk.Frame(top); btns.pack(pady=10)
        ttk.Button(btns, text="Generate", command=generate).pack(side=tk.LEFT, padx=5)
        ttk.Button(btns, text="Copy", command=copy_to_clipboard).pack(side=tk.LEFT, padx=5)
        ttk.Button(btns, text="Close", command=top.destroy).pack(side=tk.LEFT, padx=5)

    def generate_password_for_entry(self):
        def apply_password():
            self.entry_vars['password'].delete(0, tk.END)
            self.entry_vars['password'].insert(0, password_var.get())
            top.destroy()

        def generate():
            length = length_var.get()
            length = 12 if length < 8 or length > 50 else length
            chars = string.ascii_letters + string.digits + string.punctuation
            password_var.set(''.join(secrets.choice(chars) for _ in range(length)))

        top = tk.Toplevel(self.root)
        top.title("Generate Password")
        top.geometry("400x260")

        ttk.Label(top, text="Generate Password", font=('Arial', 14, 'bold')).pack(pady=10)
        length_var = tk.IntVar(value=12)
        ttk.Label(top, text="Length:").pack()
        ttk.Spinbox(top, from_=8, to=50, textvariable=length_var, width=6).pack()

        password_var = tk.StringVar()
        ttk.Entry(top, textvariable=password_var, state='readonly').pack(pady=10, ipadx=50)

        btns = ttk.Frame(top); btns.pack(pady=10)
        ttk.Button(btns, text="Generate", command=generate).pack(side=tk.LEFT, padx=5)
        ttk.Button(btns, text="Apply", command=apply_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(btns, text="Cancel", command=top.destroy).pack(side=tk.LEFT, padx=5)

        generate()  # initial

    def toggle_password_visibility(self):
        current = self.entry_vars['password']
        current_show = current.cget('show')
        if current_show == '':
            current.config(show='•')
        else:
            current.config(show='')

    def copy_password_to_clipboard(self):
        password = self.entry_vars['password'].get()
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Copied", "Password copied to clipboard")
        else:
            messagebox.showwarning("Warning", "No password to copy")

    def logout(self):
        # Clear sensitive data from memory
        self.fernet_key = None
        self.master_password_hash = None
        self.current_edit = None
        self.set_locked_ui(True)
        if hasattr(self, 'master_pw_entry'):
            self.master_pw_entry.delete(0, tk.END)
        self.show_login()

    def clear_clipboard(self):
        pyperclip.copy('')
        messagebox.showinfo("Clipboard", "Clipboard cleared")


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
