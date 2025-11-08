"""Alternative GUI using standard tkinter for compatibility."""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
from pathlib import Path

from src.encryptors import FernetEncryptor, AESEncryptor, RSAEncryptor
from src.utils import FileHandler


class EncryptionToolGUI:
    """Encryption Tool GUI using standard tkinter."""

    # Colors - Application branding
    DAVENPORT_RED = "#C8102E"
    DAVENPORT_BLACK = "#1F1F1F"
    DAVENPORT_WHITE = "#FFFFFF"
    BG_COLOR = "#F5F5F5"
    TEXT_COLOR = "#333333"

    def __init__(self, root):
        """Initialize the GUI."""
        self.root = root
        self.root.title("File Encryption Tool")
        self.root.geometry("900x650")
        self.root.resizable(True, True)
        self.root.configure(bg=self.BG_COLOR)

        # Configure style
        style = ttk.Style()
        style.theme_use("aqua")

        # Create main frame
        self._create_widgets()

        # Center window
        self._center_window()

    def _create_widgets(self):
        """Create all GUI widgets."""
        # Header frame
        header = tk.Frame(self.root, bg=self.DAVENPORT_RED, height=80)
        header.pack(fill="x", pady=0)
        header.pack_propagate(False)

        # Title in header
        title_label = tk.Label(
            header,
            text="File Encryption Tool",
            font=("Helvetica", 24, "bold"),
            bg=self.DAVENPORT_RED,
            fg=self.DAVENPORT_WHITE,
        )
        title_label.pack(pady=10)

        subtitle_label = tk.Label(
            header,
            text="Secure File Encryption",
            font=("Helvetica", 10),
            bg=self.DAVENPORT_RED,
            fg=self.DAVENPORT_WHITE,
        )
        subtitle_label.pack()

        # Notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # Create tabs
        self.encrypt_tab = tk.Frame(self.notebook, bg=self.BG_COLOR)
        self.decrypt_tab = tk.Frame(self.notebook, bg=self.BG_COLOR)
        self.keygen_tab = tk.Frame(self.notebook, bg=self.BG_COLOR)

        self.notebook.add(self.encrypt_tab, text="Encrypt")
        self.notebook.add(self.decrypt_tab, text="Decrypt")
        self.notebook.add(self.keygen_tab, text="Key Generation")

        # Create tab contents
        self._create_encrypt_tab()
        self._create_decrypt_tab()
        self._create_keygen_tab()

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(
            self.root,
            textvariable=self.status_var,
            bg=self.DAVENPORT_BLACK,
            fg=self.DAVENPORT_WHITE,
            anchor="w",
            padx=10,
            pady=5,
        )
        status_bar.pack(fill="x", side="bottom")

    def _create_encrypt_tab(self):
        """Create encryption tab."""
        frame = tk.Frame(self.encrypt_tab, bg=self.BG_COLOR)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Input file
        tk.Label(
            frame,
            text="Input File:",
            font=("Helvetica", 10, "bold"),
            bg=self.BG_COLOR,
        ).pack(anchor="w", pady=(10, 0))

        input_frame = tk.Frame(frame, bg=self.BG_COLOR)
        input_frame.pack(fill="x", pady=(0, 10))

        self.encrypt_input_var = tk.StringVar()
        tk.Entry(
            input_frame, textvariable=self.encrypt_input_var, width=50
        ).pack(side="left", fill="x", expand=True, padx=(0, 5))
        tk.Button(
            input_frame,
            text="Browse",
            command=lambda: self._browse_file("encrypt_input"),
            bg=self.DAVENPORT_RED,
            fg=self.DAVENPORT_WHITE,
        ).pack(side="left")

        # Algorithm
        tk.Label(
            frame,
            text="Algorithm:",
            font=("Helvetica", 10, "bold"),
            bg=self.BG_COLOR,
        ).pack(anchor="w", pady=(10, 5))

        self.encrypt_algo_var = tk.StringVar(value="fernet")
        algo_frame = tk.Frame(frame, bg=self.BG_COLOR)
        algo_frame.pack(fill="x", pady=(0, 10))

        for algo in ["fernet", "aes"]:
            tk.Radiobutton(
                algo_frame,
                text=algo.upper(),
                variable=self.encrypt_algo_var,
                value=algo,
                bg=self.BG_COLOR,
            ).pack(side="left", padx=10)

        # Key file
        tk.Label(
            frame,
            text="Encryption Key:",
            font=("Helvetica", 10, "bold"),
            bg=self.BG_COLOR,
        ).pack(anchor="w", pady=(10, 0))

        key_frame = tk.Frame(frame, bg=self.BG_COLOR)
        key_frame.pack(fill="x", pady=(0, 10))

        self.encrypt_key_var = tk.StringVar()
        tk.Entry(key_frame, textvariable=self.encrypt_key_var, width=50).pack(
            side="left", fill="x", expand=True, padx=(0, 5)
        )
        tk.Button(
            key_frame,
            text="Browse",
            command=lambda: self._browse_file("encrypt_key"),
            bg=self.DAVENPORT_RED,
            fg=self.DAVENPORT_WHITE,
        ).pack(side="left")

        # Output file
        tk.Label(
            frame,
            text="Output File:",
            font=("Helvetica", 10, "bold"),
            bg=self.BG_COLOR,
        ).pack(anchor="w", pady=(10, 0))

        output_frame = tk.Frame(frame, bg=self.BG_COLOR)
        output_frame.pack(fill="x", pady=(0, 20))

        self.encrypt_output_var = tk.StringVar()
        tk.Entry(
            output_frame, textvariable=self.encrypt_output_var, width=50
        ).pack(side="left", fill="x", expand=True, padx=(0, 5))
        tk.Button(
            output_frame,
            text="Browse",
            command=lambda: self._browse_save_file("encrypt_output"),
            bg=self.DAVENPORT_RED,
            fg=self.DAVENPORT_WHITE,
        ).pack(side="left")

        # Buttons
        button_frame = tk.Frame(frame, bg=self.BG_COLOR)
        button_frame.pack(fill="x", pady=(20, 0))

        self.encrypt_btn = tk.Button(
            button_frame,
            text="Encrypt File",
            command=self._encrypt_file,
            bg=self.DAVENPORT_RED,
            fg=self.DAVENPORT_WHITE,
            font=("Helvetica", 11, "bold"),
            padx=20,
            pady=10,
        )
        self.encrypt_btn.pack(side="left", padx=(0, 5), fill="both", expand=True)

        tk.Button(
            button_frame,
            text="Clear",
            command=lambda: self._clear_encrypt(),
            bg=self.DAVENPORT_BLACK,
            fg=self.DAVENPORT_WHITE,
            font=("Helvetica", 11, "bold"),
            padx=20,
            pady=10,
        ).pack(side="left", fill="both", expand=True)

    def _create_decrypt_tab(self):
        """Create decryption tab."""
        frame = tk.Frame(self.decrypt_tab, bg=self.BG_COLOR)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Input file
        tk.Label(
            frame,
            text="Encrypted File:",
            font=("Helvetica", 10, "bold"),
            bg=self.BG_COLOR,
        ).pack(anchor="w", pady=(10, 0))

        input_frame = tk.Frame(frame, bg=self.BG_COLOR)
        input_frame.pack(fill="x", pady=(0, 10))

        self.decrypt_input_var = tk.StringVar()
        tk.Entry(
            input_frame, textvariable=self.decrypt_input_var, width=50
        ).pack(side="left", fill="x", expand=True, padx=(0, 5))
        tk.Button(
            input_frame,
            text="Browse",
            command=lambda: self._browse_file("decrypt_input"),
            bg=self.DAVENPORT_RED,
            fg=self.DAVENPORT_WHITE,
        ).pack(side="left")

        # Algorithm
        tk.Label(
            frame,
            text="Algorithm:",
            font=("Helvetica", 10, "bold"),
            bg=self.BG_COLOR,
        ).pack(anchor="w", pady=(10, 5))

        self.decrypt_algo_var = tk.StringVar(value="fernet")
        algo_frame = tk.Frame(frame, bg=self.BG_COLOR)
        algo_frame.pack(fill="x", pady=(0, 10))

        for algo in ["fernet", "aes"]:
            tk.Radiobutton(
                algo_frame,
                text=algo.upper(),
                variable=self.decrypt_algo_var,
                value=algo,
                bg=self.BG_COLOR,
            ).pack(side="left", padx=10)

        # Key file
        tk.Label(
            frame,
            text="Decryption Key:",
            font=("Helvetica", 10, "bold"),
            bg=self.BG_COLOR,
        ).pack(anchor="w", pady=(10, 0))

        key_frame = tk.Frame(frame, bg=self.BG_COLOR)
        key_frame.pack(fill="x", pady=(0, 10))

        self.decrypt_key_var = tk.StringVar()
        tk.Entry(key_frame, textvariable=self.decrypt_key_var, width=50).pack(
            side="left", fill="x", expand=True, padx=(0, 5)
        )
        tk.Button(
            key_frame,
            text="Browse",
            command=lambda: self._browse_file("decrypt_key"),
            bg=self.DAVENPORT_RED,
            fg=self.DAVENPORT_WHITE,
        ).pack(side="left")

        # Output file
        tk.Label(
            frame,
            text="Output File:",
            font=("Helvetica", 10, "bold"),
            bg=self.BG_COLOR,
        ).pack(anchor="w", pady=(10, 0))

        output_frame = tk.Frame(frame, bg=self.BG_COLOR)
        output_frame.pack(fill="x", pady=(0, 20))

        self.decrypt_output_var = tk.StringVar()
        tk.Entry(
            output_frame, textvariable=self.decrypt_output_var, width=50
        ).pack(side="left", fill="x", expand=True, padx=(0, 5))
        tk.Button(
            output_frame,
            text="Browse",
            command=lambda: self._browse_save_file("decrypt_output"),
            bg=self.DAVENPORT_RED,
            fg=self.DAVENPORT_WHITE,
        ).pack(side="left")

        # Buttons
        button_frame = tk.Frame(frame, bg=self.BG_COLOR)
        button_frame.pack(fill="x", pady=(20, 0))

        self.decrypt_btn = tk.Button(
            button_frame,
            text="Decrypt File",
            command=self._decrypt_file,
            bg=self.DAVENPORT_RED,
            fg=self.DAVENPORT_WHITE,
            font=("Helvetica", 11, "bold"),
            padx=20,
            pady=10,
        )
        self.decrypt_btn.pack(side="left", padx=(0, 5), fill="both", expand=True)

        tk.Button(
            button_frame,
            text="Clear",
            command=lambda: self._clear_decrypt(),
            bg=self.DAVENPORT_BLACK,
            fg=self.DAVENPORT_WHITE,
            font=("Helvetica", 11, "bold"),
            padx=20,
            pady=10,
        ).pack(side="left", fill="both", expand=True)

    def _create_keygen_tab(self):
        """Create key generation tab."""
        frame = tk.Frame(self.keygen_tab, bg=self.BG_COLOR)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Symmetric keys section
        tk.Label(
            frame,
            text="Symmetric Key Generation (Fernet & AES-256)",
            font=("Helvetica", 12, "bold"),
            bg=self.BG_COLOR,
            fg=self.DAVENPORT_RED,
        ).pack(anchor="w", pady=(10, 10))

        sym_frame = tk.Frame(frame, bg=self.BG_COLOR)
        sym_frame.pack(fill="x", pady=(0, 20))

        # Algorithm selection
        algo_frame = tk.Frame(sym_frame, bg=self.BG_COLOR)
        algo_frame.pack(fill="x", pady=(0, 10))

        tk.Label(
            algo_frame,
            text="Algorithm:",
            font=("Helvetica", 10),
            bg=self.BG_COLOR,
        ).pack(side="left", padx=(0, 10))

        self.keygen_sym_algo_var = tk.StringVar(value="fernet")
        for algo in ["fernet", "aes"]:
            tk.Radiobutton(
                algo_frame,
                text=algo.upper(),
                variable=self.keygen_sym_algo_var,
                value=algo,
                bg=self.BG_COLOR,
            ).pack(side="left", padx=10)

        # Output path
        tk.Label(
            sym_frame,
            text="Save Key To:",
            font=("Helvetica", 10),
            bg=self.BG_COLOR,
        ).pack(anchor="w", pady=(0, 5))

        output_frame = tk.Frame(sym_frame, bg=self.BG_COLOR)
        output_frame.pack(fill="x", pady=(0, 10))

        self.keygen_sym_output_var = tk.StringVar()
        tk.Entry(
            output_frame, textvariable=self.keygen_sym_output_var, width=50
        ).pack(side="left", fill="x", expand=True, padx=(0, 5))
        tk.Button(
            output_frame,
            text="Browse",
            command=lambda: self._browse_save_file("keygen_sym_output"),
            bg=self.DAVENPORT_RED,
            fg=self.DAVENPORT_WHITE,
        ).pack(side="left")

        # Generate button
        tk.Button(
            sym_frame,
            text="Generate Symmetric Key",
            command=self._generate_symmetric_key,
            bg=self.DAVENPORT_RED,
            fg=self.DAVENPORT_WHITE,
            font=("Helvetica", 11, "bold"),
            padx=20,
            pady=10,
        ).pack(fill="x")

        # Separator
        ttk.Separator(frame, orient="horizontal").pack(fill="x", pady=20)

        # RSA section
        tk.Label(
            frame,
            text="RSA Keypair Generation (Asymmetric)",
            font=("Helvetica", 12, "bold"),
            bg=self.BG_COLOR,
            fg=self.DAVENPORT_RED,
        ).pack(anchor="w", pady=(10, 10))

        rsa_frame = tk.Frame(frame, bg=self.BG_COLOR)
        rsa_frame.pack(fill="x")

        tk.Label(
            rsa_frame,
            text="Save Keypair To (prefix):",
            font=("Helvetica", 10),
            bg=self.BG_COLOR,
        ).pack(anchor="w", pady=(0, 5))

        output_frame = tk.Frame(rsa_frame, bg=self.BG_COLOR)
        output_frame.pack(fill="x", pady=(0, 10))

        self.keygen_rsa_output_var = tk.StringVar()
        tk.Entry(
            output_frame, textvariable=self.keygen_rsa_output_var, width=50
        ).pack(side="left", fill="x", expand=True, padx=(0, 5))
        tk.Button(
            output_frame,
            text="Browse",
            command=self._browse_directory,
            bg=self.DAVENPORT_RED,
            fg=self.DAVENPORT_WHITE,
        ).pack(side="left")

        # Generate button
        tk.Button(
            rsa_frame,
            text="Generate RSA Keypair",
            command=self._generate_rsa_keypair,
            bg=self.DAVENPORT_RED,
            fg=self.DAVENPORT_WHITE,
            font=("Helvetica", 11, "bold"),
            padx=20,
            pady=10,
        ).pack(fill="x")

    def _browse_file(self, var_name):
        """Browse for a file."""
        file_path = filedialog.askopenfilename()
        if file_path:
            if var_name == "encrypt_input":
                self.encrypt_input_var.set(file_path)
            elif var_name == "encrypt_key":
                self.encrypt_key_var.set(file_path)
            elif var_name == "decrypt_input":
                self.decrypt_input_var.set(file_path)
            elif var_name == "decrypt_key":
                self.decrypt_key_var.set(file_path)

    def _browse_save_file(self, var_name):
        """Browse for a save location."""
        file_path = filedialog.asksaveasfilename()
        if file_path:
            if var_name == "encrypt_output":
                self.encrypt_output_var.set(file_path)
            elif var_name == "decrypt_output":
                self.decrypt_output_var.set(file_path)
            elif var_name == "keygen_sym_output":
                self.keygen_sym_output_var.set(file_path)

    def _browse_directory(self):
        """Browse for a directory."""
        directory = filedialog.askdirectory()
        if directory:
            self.keygen_rsa_output_var.set(directory)

    def _encrypt_file(self):
        """Encrypt the file."""
        if not self.encrypt_input_var.get():
            messagebox.showerror("Error", "Please select an input file")
            return

        if not self.encrypt_key_var.get():
            messagebox.showerror("Error", "Please select a key file")
            return

        if not self.encrypt_output_var.get():
            messagebox.showerror("Error", "Please specify an output file")
            return

        self.encrypt_btn.config(state="disabled")
        self.status_var.set("Encrypting...")

        def do_encrypt():
            try:
                input_file = self.encrypt_input_var.get()
                output_file = self.encrypt_output_var.get()
                key_file = self.encrypt_key_var.get()
                algorithm = self.encrypt_algo_var.get()

                if algorithm == "fernet":
                    key = FernetEncryptor.load_key(key_file)
                    FernetEncryptor.encrypt_file(input_file, output_file, key)
                elif algorithm == "aes":
                    key = AESEncryptor.load_key(key_file)
                    AESEncryptor.encrypt_file(input_file, output_file, key)

                self.status_var.set("✓ File encrypted successfully")
                messagebox.showinfo(
                    "Success", f"File encrypted successfully!\nOutput: {output_file}"
                )
            except Exception as e:
                self.status_var.set("✗ Encryption failed")
                messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            finally:
                self.encrypt_btn.config(state="normal")

        thread = threading.Thread(target=do_encrypt)
        thread.daemon = True
        thread.start()

    def _decrypt_file(self):
        """Decrypt the file."""
        if not self.decrypt_input_var.get():
            messagebox.showerror("Error", "Please select an encrypted file")
            return

        if not self.decrypt_key_var.get():
            messagebox.showerror("Error", "Please select a key file")
            return

        if not self.decrypt_output_var.get():
            messagebox.showerror("Error", "Please specify an output file")
            return

        self.decrypt_btn.config(state="disabled")
        self.status_var.set("Decrypting...")

        def do_decrypt():
            try:
                input_file = self.decrypt_input_var.get()
                output_file = self.decrypt_output_var.get()
                key_file = self.decrypt_key_var.get()
                algorithm = self.decrypt_algo_var.get()

                if algorithm == "fernet":
                    key = FernetEncryptor.load_key(key_file)
                    FernetEncryptor.decrypt_file(input_file, output_file, key)
                elif algorithm == "aes":
                    key = AESEncryptor.load_key(key_file)
                    AESEncryptor.decrypt_file(input_file, output_file, key)

                self.status_var.set("✓ File decrypted successfully")
                messagebox.showinfo(
                    "Success", f"File decrypted successfully!\nOutput: {output_file}"
                )
            except Exception as e:
                self.status_var.set("✗ Decryption failed")
                messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            finally:
                self.decrypt_btn.config(state="normal")

        thread = threading.Thread(target=do_decrypt)
        thread.daemon = True
        thread.start()

    def _generate_symmetric_key(self):
        """Generate a symmetric key."""
        if not self.keygen_sym_output_var.get():
            messagebox.showerror("Error", "Please specify an output file")
            return

        self.status_var.set("Generating key...")

        def do_generate():
            try:
                output_path = os.path.expanduser(self.keygen_sym_output_var.get())
                os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

                algorithm = self.keygen_sym_algo_var.get()

                if algorithm == "fernet":
                    key = FernetEncryptor.generate_key()
                    FernetEncryptor.save_key(key, output_path)
                    algo_name = "Fernet"
                elif algorithm == "aes":
                    key = AESEncryptor.generate_key()
                    AESEncryptor.save_key(key, output_path)
                    algo_name = "AES-256"

                self.status_var.set(f"✓ {algo_name} key generated")
                messagebox.showinfo(
                    "Success",
                    f"{algo_name} key generated successfully!\nFile: {output_path}",
                )
            except Exception as e:
                self.status_var.set("✗ Key generation failed")
                messagebox.showerror("Error", str(e))

        thread = threading.Thread(target=do_generate)
        thread.daemon = True
        thread.start()

    def _generate_rsa_keypair(self):
        """Generate RSA keypair."""
        if not self.keygen_rsa_output_var.get():
            messagebox.showerror("Error", "Please specify an output location")
            return

        self.status_var.set("Generating RSA keypair (this may take a moment)...")

        def do_generate():
            try:
                output_prefix = os.path.expanduser(self.keygen_rsa_output_var.get())
                os.makedirs(os.path.dirname(output_prefix) or ".", exist_ok=True)

                private_key, public_key = RSAEncryptor.generate_key_pair()

                private_path = f"{output_prefix}_private.pem"
                public_path = f"{output_prefix}_public.pem"

                RSAEncryptor.save_private_key(private_key, private_path)
                RSAEncryptor.save_public_key(public_key, public_path)

                self.status_var.set("✓ RSA keypair generated")
                messagebox.showinfo(
                    "Success",
                    f"RSA keypair generated successfully!\n"
                    f"Private: {private_path}\n"
                    f"Public: {public_path}",
                )
            except Exception as e:
                self.status_var.set("✗ Keypair generation failed")
                messagebox.showerror("Error", str(e))

        thread = threading.Thread(target=do_generate)
        thread.daemon = True
        thread.start()

    def _clear_encrypt(self):
        """Clear encryption fields."""
        self.encrypt_input_var.set("")
        self.encrypt_key_var.set("")
        self.encrypt_output_var.set("")

    def _clear_decrypt(self):
        """Clear decryption fields."""
        self.decrypt_input_var.set("")
        self.decrypt_key_var.set("")
        self.decrypt_output_var.set("")

    def _center_window(self):
        """Center window on screen."""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def run(self):
        """Run the application."""
        self.root.mainloop()


def main():
    """Entry point for the GUI."""
    root = tk.Tk()
    app = EncryptionToolGUI(root)
    app.run()


if __name__ == "__main__":
    main()
