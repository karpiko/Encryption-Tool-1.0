"""Key Generation tab for the GUI."""

import customtkinter as ctk
import os
from .styles import *
from .utils import FileDialogHelper, MessageHelper, ThreadHelper
from src.encryptors import FernetEncryptor, AESEncryptor, RSAEncryptor


class KeyGenTab(ctk.CTkFrame):
    """Key Generation tab content."""

    def __init__(self, parent, app):
        """Initialize key generation tab."""
        super().__init__(parent, fg_color=BACKGROUND_COLOR)
        self.app = app
        self.pack(fill="both", expand=True, padx=PADDING, pady=PADDING)

        self._create_widgets()

    def _create_widgets(self):
        """Create tab widgets."""
        # Title
        title = ctk.CTkLabel(
            self,
            text="Generate Encryption Keys",
            text_color=DAVENPORT_RED,
            font=SUBTITLE_FONT,
            anchor="w",
        )
        title.pack(anchor="w", pady=(0, PADDING))

        # Symmetric key generation
        self._create_symmetric_section()

        # RSA key generation
        self._create_rsa_section()

    def _create_symmetric_section(self):
        """Create symmetric key generation section."""
        sym_frame = ctk.CTkFrame(self, fg_color=DAVENPORT_WHITE, corner_radius=10)
        sym_frame.pack(fill="x", pady=(0, 20))

        # Header
        header = ctk.CTkLabel(
            sym_frame,
            text="Symmetric Keys (Fernet & AES-256)",
            text_color=DAVENPORT_RED,
            font=LABEL_FONT,
            anchor="w",
        )
        header.pack(anchor="w", padx=PADDING, pady=(PADDING, 10))

        # Algorithm selection
        algo_frame = ctk.CTkFrame(sym_frame, fg_color=DAVENPORT_WHITE)
        algo_frame.pack(fill="x", padx=PADDING, pady=(0, 15))

        algo_label = ctk.CTkLabel(
            algo_frame,
            text="Algorithm:",
            text_color=TEXT_COLOR,
            font=LABEL_FONT,
        )
        algo_label.pack(side="left", padx=(0, 15))

        self.sym_algorithm_var = ctk.StringVar(value="fernet")

        for algo in ["Fernet", "AES-256"]:
            radio = ctk.CTkRadioButton(
                algo_frame,
                text=algo,
                variable=self.sym_algorithm_var,
                value=algo.lower().replace("-", ""),
                text_color=TEXT_COLOR,
                fg_color=DAVENPORT_RED,
                hover_color="#A00A24",
            )
            radio.pack(side="left", padx=10)

        # Output path
        output_frame = ctk.CTkFrame(sym_frame, fg_color=DAVENPORT_WHITE)
        output_frame.pack(fill="x", padx=PADDING, pady=(0, 15))
        output_frame.grid_columnconfigure(0, weight=1)

        output_label = ctk.CTkLabel(
            output_frame,
            text="Save Key To:",
            text_color=TEXT_COLOR,
            font=LABEL_FONT,
        )
        output_label.pack(anchor="w", pady=(0, 5))

        self.sym_output_var = ctk.StringVar()
        self.sym_output_entry = ctk.CTkEntry(
            output_frame,
            textvariable=self.sym_output_var,
            placeholder_text="Enter file path (e.g., ~/my_key.key)...",
            **ENTRY_CONFIG,
        )
        self.sym_output_entry.pack(fill="x", pady=(0, 10))

        browse_subframe = ctk.CTkFrame(output_frame, fg_color=DAVENPORT_WHITE)
        browse_subframe.pack(fill="x")
        browse_subframe.grid_columnconfigure(0, weight=1)

        self.sym_browse_btn = ctk.CTkButton(
            browse_subframe,
            text="Browse...",
            command=self._browse_sym_output,
            **BUTTON_SECONDARY_CONFIG,
            width=150,
        )
        self.sym_browse_btn.pack(side="right")

        # Info
        info_label = ctk.CTkLabel(
            sym_frame,
            text="Keys are generated securely and saved to disk. Keep them safe!",
            text_color=DAVENPORT_DARK_GRAY,
            font=("Segoe UI", 9),
            anchor="w",
        )
        info_label.pack(anchor="w", padx=PADDING, pady=(0, 15))

        # Generate button
        generate_btn = ctk.CTkButton(
            sym_frame,
            text="Generate Symmetric Key",
            command=self._generate_symmetric_key,
            **BUTTON_CONFIG,
        )
        generate_btn.pack(fill="x", padx=PADDING, pady=(0, PADDING))

    def _create_rsa_section(self):
        """Create RSA key pair generation section."""
        rsa_frame = ctk.CTkFrame(self, fg_color=DAVENPORT_WHITE, corner_radius=10)
        rsa_frame.pack(fill="x")

        # Header
        header = ctk.CTkLabel(
            rsa_frame,
            text="RSA Keypair (Asymmetric)",
            text_color=DAVENPORT_RED,
            font=LABEL_FONT,
            anchor="w",
        )
        header.pack(anchor="w", padx=PADDING, pady=(PADDING, 10))

        # Output path
        output_frame = ctk.CTkFrame(rsa_frame, fg_color=DAVENPORT_WHITE)
        output_frame.pack(fill="x", padx=PADDING, pady=(0, 15))
        output_frame.grid_columnconfigure(0, weight=1)

        output_label = ctk.CTkLabel(
            output_frame,
            text="Save Keypair To (prefix):",
            text_color=TEXT_COLOR,
            font=LABEL_FONT,
        )
        output_label.pack(anchor="w", pady=(0, 5))

        self.rsa_output_var = ctk.StringVar()
        self.rsa_output_entry = ctk.CTkEntry(
            output_frame,
            textvariable=self.rsa_output_var,
            placeholder_text="Enter prefix (e.g., ~/my_rsa) - creates my_rsa_private.pem and my_rsa_public.pem...",
            **ENTRY_CONFIG,
        )
        self.rsa_output_entry.pack(fill="x", pady=(0, 10))

        browse_subframe = ctk.CTkFrame(output_frame, fg_color=DAVENPORT_WHITE)
        browse_subframe.pack(fill="x")
        browse_subframe.grid_columnconfigure(0, weight=1)

        self.rsa_browse_btn = ctk.CTkButton(
            browse_subframe,
            text="Browse...",
            command=self._browse_rsa_output,
            **BUTTON_SECONDARY_CONFIG,
            width=150,
        )
        self.rsa_browse_btn.pack(side="right")

        # Info
        info_frame = ctk.CTkFrame(rsa_frame, fg_color=DAVENPORT_WHITE)
        info_frame.pack(fill="x", padx=PADDING, pady=(0, 15))

        info_label = ctk.CTkLabel(
            info_frame,
            text="Creates two files:",
            text_color=DAVENPORT_DARK_GRAY,
            font=("Segoe UI", 9),
            anchor="w",
        )
        info_label.pack(anchor="w")

        info_label2 = ctk.CTkLabel(
            info_frame,
            text="• prefix_private.pem (keep secret!)\n• prefix_public.pem (can be shared)",
            text_color=DAVENPORT_DARK_GRAY,
            font=("Segoe UI", 9),
            anchor="w",
            justify="left",
        )
        info_label2.pack(anchor="w")

        # Generate button
        generate_btn = ctk.CTkButton(
            rsa_frame,
            text="Generate RSA Keypair",
            command=self._generate_rsa_keypair,
            **BUTTON_CONFIG,
        )
        generate_btn.pack(fill="x", padx=PADDING, pady=(0, PADDING))

    def _browse_sym_output(self):
        """Browse for symmetric key output location."""
        file_path = FileDialogHelper.select_save_file(
            title="Save key as",
            filetypes=[("Key Files", "*.key"), ("All Files", "*.*")],
            defaultext=".key",
        )

        if file_path:
            self.sym_output_var.set(file_path)

    def _browse_rsa_output(self):
        """Browse for RSA keypair output location."""
        directory = FileDialogHelper.select_directory(title="Select directory for RSA keys")

        if directory:
            # Use directory as prefix
            default_name = os.path.join(directory, "encryption_key")
            self.rsa_output_var.set(default_name)

    def _generate_symmetric_key(self):
        """Generate a symmetric key."""
        if not self.sym_output_var.get():
            MessageHelper.show_error("Input Error", "Please specify an output file")
            return

        self.app.update_status("Generating key...", "info")

        def do_generate():
            try:
                output_path = self.sym_output_var.get()
                algorithm = self.sym_algorithm_var.get()

                # Expand ~ in path
                output_path = os.path.expanduser(output_path)

                # Create directory if needed
                os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

                if algorithm == "fernet":
                    key = FernetEncryptor.generate_key()
                    FernetEncryptor.save_key(key, output_path)
                    algo_name = "Fernet"
                elif algorithm == "aes256":
                    key = AESEncryptor.generate_key()
                    AESEncryptor.save_key(key, output_path)
                    algo_name = "AES-256"

                self.app.update_status(
                    f"✓ {algo_name} key generated successfully", "success"
                )
                MessageHelper.show_success(
                    "Success",
                    f"{algo_name} key generated successfully!\n\n"
                    f"File: {output_path}\n\n"
                    f"⚠ Keep this key safe! Don't share or lose it.",
                )

            except Exception as e:
                self.app.update_status(f"Key generation failed: {str(e)}", "error")
                MessageHelper.show_error("Generation Error", str(e))

        ThreadHelper.run_in_thread(do_generate)

    def _generate_rsa_keypair(self):
        """Generate RSA keypair."""
        if not self.rsa_output_var.get():
            MessageHelper.show_error("Input Error", "Please specify output prefix")
            return

        self.app.update_status("Generating RSA keypair (this may take a moment)...", "info")

        def do_generate():
            try:
                output_prefix = self.rsa_output_var.get()

                # Expand ~ in path
                output_prefix = os.path.expanduser(output_prefix)

                # Create directory if needed
                os.makedirs(os.path.dirname(output_prefix) or ".", exist_ok=True)

                # Generate keypair
                private_key, public_key = RSAEncryptor.generate_key_pair()

                # Save keys
                private_path = f"{output_prefix}_private.pem"
                public_path = f"{output_prefix}_public.pem"

                RSAEncryptor.save_private_key(private_key, private_path)
                RSAEncryptor.save_public_key(public_key, public_path)

                self.app.update_status("✓ RSA keypair generated successfully", "success")
                MessageHelper.show_success(
                    "Success",
                    f"RSA keypair generated successfully!\n\n"
                    f"Private Key: {private_path}\n"
                    f"Public Key: {public_path}\n\n"
                    f"⚠ Keep the private key safe! Never share it.",
                )

            except Exception as e:
                self.app.update_status(f"Keypair generation failed: {str(e)}", "error")
                MessageHelper.show_error("Generation Error", str(e))

        ThreadHelper.run_in_thread(do_generate)
