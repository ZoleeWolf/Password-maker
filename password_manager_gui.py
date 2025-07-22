"""password_manager_gui.py – v1.1  (clipboard support)

• New **Copy** button to copy the last generated password/token.
• When you *Show* a stored password it is automatically copied to the clipboard
  and the message box tells you so.

Run with:  python password_manager_gui.py
"""
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

from password_generator import generate_password  # existing logic
from password_crypto import encrypt_password, decrypt_password
from password_store import (
    add_entry,
    fetch_entry,
    list_labels,
    delete_entry,
    STORE_PATH,
)


class PasswordManagerGUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Password Manager")
        self.geometry("620x420")
        self.resizable(False, False)

        # ─── Generator frame ────────────────────────────────────────────────
        gen_frame = ttk.Labelframe(self, text="Generate & Encrypt")
        gen_frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(gen_frame, text="Length:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.len_spin = ttk.Spinbox(gen_frame, from_=3, to=64, width=5)
        self.len_spin.set(16)
        self.len_spin.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(gen_frame, text="Passphrase (optional):").grid(row=0, column=2, padx=5, pady=5, sticky="e")
        self.pass_entry = ttk.Entry(gen_frame, show="*", width=20)
        self.pass_entry.grid(row=0, column=3, padx=5, pady=5)

        self.gen_btn = ttk.Button(gen_frame, text="Generate", command=self._generate)
        self.gen_btn.grid(row=0, column=4, padx=5, pady=5)

        self.generated_var = tk.StringVar()
        gen_entry = ttk.Entry(gen_frame, textvariable=self.generated_var, width=72, state="readonly")
        gen_entry.grid(row=1, column=0, columnspan=4, padx=5, pady=5, sticky="we")

        self.copy_btn = ttk.Button(gen_frame, text="Copy", command=self._copy_generated)
        self.copy_btn.grid(row=1, column=4, padx=5, pady=5)

        # ─── Vault frame ────────────────────────────────────────────────────
        vault_frame = ttk.Labelframe(self, text=f"Vault ({STORE_PATH})")
        vault_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.label_list = tk.Listbox(vault_frame, height=10)
        self.label_list.pack(side="left", fill="both", expand=True, padx=(5, 0), pady=5)
        self.label_list.bind("<<ListboxSelect>>", self._show_selected)

        btn_frame = ttk.Frame(vault_frame)
        btn_frame.pack(side="right", fill="y", padx=5, pady=5)

        ttk.Button(btn_frame, text="🔄 Refresh", command=self._refresh).pack(fill="x", pady=2)
        ttk.Button(btn_frame, text="➕ Add", command=self._add_current).pack(fill="x", pady=2)
        ttk.Button(btn_frame, text="👁 Show", command=self._show_selected).pack(fill="x", pady=2)
        ttk.Button(btn_frame, text="🗑 Delete", command=self._delete_selected).pack(fill="x", pady=2)

        self._refresh()

    # ────────────────────────────────────────────────────────────────────
    # Generator callbacks
    # ────────────────────────────────────────────────────────────────────

    def _generate(self) -> None:
        try:
            length = int(self.len_spin.get())
            pw = generate_password(length)
        except ValueError as exc:
            messagebox.showerror("Error", str(exc))
            return

        passphrase = self.pass_entry.get()
        if passphrase:
            token = encrypt_password(pw, passphrase)
            self.generated_var.set(token)
        else:
            self.generated_var.set(pw)

    def _copy_generated(self) -> None:
        content = self.generated_var.get()
        if not content:
            messagebox.showinfo("Info", "Nothing to copy.")
            return
        self.clipboard_clear()
        self.clipboard_append(content)
        self.update()  # now it’s in the clipboard for sure
        messagebox.showinfo("Copied", "Copied to clipboard.")

    def _add_current(self) -> None:
        token = self.generated_var.get()
        if not token:
            messagebox.showinfo("Info", "Nothing to add. Generate first.")
            return
        label = simpledialog.askstring("Label", "Name for this entry:")
        if not label:
            return
        add_entry(label, token)
        self._refresh()
        messagebox.showinfo("Saved", f"Entry '{label}' saved to vault.")

    # ────────────────────────────────────────────────────────────────────
    # Vault callbacks
    # ────────────────────────────────────────────────────────────────────

    def _refresh(self) -> None:
        self.label_list.delete(0, tk.END)
        for lbl in list_labels():
            self.label_list.insert(tk.END, lbl)

    def _get_selected_label(self) -> str | None:
        sel = self.label_list.curselection()
        if not sel:
            messagebox.showinfo("Info", "Select a label first.")
            return None
        return self.label_list.get(sel[0])

    def _show_selected(self, *_):  # event arg ignored
        label = self._get_selected_label()
        if not label:
            return
        token = fetch_entry(label)
        if token is None:
            messagebox.showerror("Error", "Label not found.")
            self._refresh()
            return
        passphrase = simpledialog.askstring("Passphrase", "Enter passphrase:", show="*")
        if passphrase is None:
            return
        try:
            pw = decrypt_password(token, passphrase)
        except Exception as exc:  # pylint: disable=broad-except
            messagebox.showerror("Error", f"Decryption failed: {exc}")
            return

        # Copy to clipboard automatically
        self.clipboard_clear()
        self.clipboard_append(pw)
        self.update()

        messagebox.showinfo(f"Password – {label}", f"{pw}\n\n(Copied to clipboard)")

    def _delete_selected(self) -> None:
        label = self._get_selected_label()
        if not label:
            return
        if messagebox.askyesno("Delete", f"Delete entry '{label}'?"):
            delete_entry(label)
            self._refresh()


if __name__ == "__main__":
    PasswordManagerGUI().mainloop()
