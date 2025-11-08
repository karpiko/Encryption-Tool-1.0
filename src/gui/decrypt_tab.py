"""Decrypt tab for the GUI."""

import customtkinter as ctk
import os
from .styles import *
from .utils import FileDialogHelper, MessageHelper, ThreadHelper, get_file_info
from src.encryptors import FernetEncryptor, AESEncryptor


class DecryptTab(ctk.CTkFrame):
    """Decrypt tab content."""

    def __init__(self, parent, app):
        """Initialize decrypt tab."""
        super().__init__(parent, fg_color=BACKGROUND_COLOR)
        self.app = app
        self.pack(fill="both", expand=True, padx=PADDING, pady=PADDING)

        self._create_widgets()

    def _create_widgets(self):
        """Create tab widgets."""
        # Title
        title = ctk.CTkLabel(
            self,
            text="Decrypt File",
            text_color=DAVENPORT_RED,
            font=SUBTITLE_FONT,
            anchor="w",
        )
        title.pack(anchor="w", pady=(0, PADDING))

        # Input file section
        self._create_file_input_section()

        # Algorithm selection
        self._create_algorithm_section()

        # Key file section
        self._create_key_section()

        # Output file section
        self._create_output_section()

        # Buttons
        self._create_buttons()

    def _create_file_input_section(self):
        """Create encrypted file selection section."""
        input_frame = ctk.CTkFrame(self, fg_color=DAVENPORT_WHITE, corner_radius=10)
        input_frame.pack(fill="x", pady=(0, 15))

        label = ctk.CTkLabel(
            input_frame,
            text="Encrypted File",
            text_color=DAVENPORT_RED,
            font=LABEL_FONT,
            anchor="w",
        )
        label.pack(anchor="w", padx=PADDING, pady=(PADDING, 5))

        input_subframe = ctk.CTkFrame(input_frame, fg_color=DAVENPORT_WHITE)
        input_subframe.pack(fill="x", padx=PADDING, pady=(0, PADDING))
        input_subframe.grid_columnconfigure(0, weight=1)

        self.input_var = ctk.StringVar()
        self.input_entry = ctk.CTkEntry(
            input_subframe,
            textvariable=self.input_var,
            placeholder_text="Select encrypted file...",
            **ENTRY_CONFIG,
        )
        self.input_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        browse_btn = ctk.CTkButton(
            input_subframe,
            text="Browse",
            command=self._browse_input_file,
            **BUTTON_CONFIG,
            width=100,
        )
        browse_btn.grid(row=0, column=1)

        # File info label
        self.input_info_label = ctk.CTkLabel(
            input_frame,
            text="",
            text_color=DAVENPORT_DARK_GRAY,
            font=("Segoe UI", 9),
            anchor="w",
        )
        self.input_info_label.pack(anchor="w", padx=PADDING, pady=(0, PADDING))

    def _create_algorithm_section(self):
        """Create algorithm selection section."""
        algo_frame = ctk.CTkFrame(self, fg_color=DAVENPORT_WHITE, corner_radius=10)
        algo_frame.pack(fill="x", pady=(0, 15))

        label = ctk.CTkLabel(
            algo_frame,
            text="Encryption Algorithm",
            text_color=DAVENPORT_RED,
            font=LABEL_FONT,
            anchor="w",
        )
        label.pack(anchor="w", padx=PADDING, pady=(PADDING, 10))

        self.algorithm_var = ctk.StringVar(value="fernet")

        algo_subframe = ctk.CTkFrame(algo_frame, fg_color=DAVENPORT_WHITE)
        algo_subframe.pack(fill="x", padx=PADDING, pady=(0, PADDING))

        # Radio buttons
        for algo in ["Fernet", "AES-256"]:
            radio = ctk.CTkRadioButton(
                algo_subframe,
                text=algo,
                variable=self.algorithm_var,
                value=algo.lower().replace("-", ""),
                text_color=TEXT_COLOR,
                fg_color=DAVENPORT_RED,
                hover_color="#A00A24",
            )
            radio.pack(side="left", padx=10)

        # Info label
        info_label = ctk.CTkLabel(
            algo_frame,
            text="⚠ Use the same algorithm that was used for encryption",
            text_color=WARNING_COLOR,
            font=("Segoe UI", 9),
            anchor="w",
        )
        info_label.pack(anchor="w", padx=PADDING, pady=(0, PADDING))

    def _create_key_section(self):
        """Create key file selection section."""
        key_frame = ctk.CTkFrame(self, fg_color=DAVENPORT_WHITE, corner_radius=10)
        key_frame.pack(fill="x", pady=(0, 15))

        label = ctk.CTkLabel(
            key_frame,
            text="Decryption Key",
            text_color=DAVENPORT_RED,
            font=LABEL_FONT,
            anchor="w",
        )
        label.pack(anchor="w", padx=PADDING, pady=(PADDING, 5))

        key_subframe = ctk.CTkFrame(key_frame, fg_color=DAVENPORT_WHITE)
        key_subframe.pack(fill="x", padx=PADDING, pady=(0, PADDING))
        key_subframe.grid_columnconfigure(0, weight=1)

        self.key_var = ctk.StringVar()
        self.key_entry = ctk.CTkEntry(
            key_subframe,
            textvariable=self.key_var,
            placeholder_text="Select decryption key file...",
            **ENTRY_CONFIG,
        )
        self.key_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        key_browse_btn = ctk.CTkButton(
            key_subframe,
            text="Browse",
            command=self._browse_key_file,
            **BUTTON_CONFIG,
            width=100,
        )
        key_browse_btn.grid(row=0, column=1)

    def _create_output_section(self):
        """Create output file selection section."""
        output_frame = ctk.CTkFrame(self, fg_color=DAVENPORT_WHITE, corner_radius=10)
        output_frame.pack(fill="x", pady=(0, 20))

        label = ctk.CTkLabel(
            output_frame,
            text="Output File",
            text_color=DAVENPORT_RED,
            font=LABEL_FONT,
            anchor="w",
        )
        label.pack(anchor="w", padx=PADDING, pady=(PADDING, 5))

        output_subframe = ctk.CTkFrame(output_frame, fg_color=DAVENPORT_WHITE)
        output_subframe.pack(fill="x", padx=PADDING, pady=(0, PADDING))
        output_subframe.grid_columnconfigure(0, weight=1)

        self.output_var = ctk.StringVar()
        self.output_entry = ctk.CTkEntry(
            output_subframe,
            textvariable=self.output_var,
            placeholder_text="Enter output file name...",
            **ENTRY_CONFIG,
        )
        self.output_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        output_browse_btn = ctk.CTkButton(
            output_subframe,
            text="Browse",
            command=self._browse_output_file,
            **BUTTON_CONFIG,
            width=100,
        )
        output_browse_btn.grid(row=0, column=1)

    def _create_buttons(self):
        """Create action buttons."""
        button_frame = ctk.CTkFrame(self, fg_color=BACKGROUND_COLOR)
        button_frame.pack(fill="x", pady=(10, 0))

        self.decrypt_btn = ctk.CTkButton(
            button_frame,
            text="Decrypt File",
            command=self._decrypt_file,
            **BUTTON_CONFIG,
        )
        self.decrypt_btn.pack(side="left", padx=(0, 10), fill="x", expand=True)

        clear_btn = ctk.CTkButton(
            button_frame,
            text="Clear",
            command=self._clear_fields,
            **BUTTON_SECONDARY_CONFIG,
        )
        clear_btn.pack(side="left", fill="x", expand=True)

    def _browse_input_file(self):
        """Browse for encrypted file."""
        file_path = FileDialogHelper.select_file(
            title="Select encrypted file",
            filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")],
        )

        if file_path:
            self.input_var.set(file_path)
            # Update file info
            file_info = get_file_info(file_path)
            if file_info:
                self.input_info_label.configure(
                    text=f"File: {file_info['name']} ({file_info['size_formatted']})"
                )

    def _browse_key_file(self):
        """Browse for key file."""
        file_path = FileDialogHelper.select_file(
            title="Select decryption key",
            filetypes=[("Key Files", "*.key"), ("All Files", "*.*")],
        )

        if file_path:
            self.key_var.set(file_path)

    def _browse_output_file(self):
        """Browse for output file location."""
        file_path = FileDialogHelper.select_save_file(
            title="Save decrypted file as", filetypes=[("All Files", "*.*")]
        )

        if file_path:
            self.output_var.set(file_path)

    def _decrypt_file(self):
        """Decrypt the file."""
        # Validation
        if not self.input_var.get():
            MessageHelper.show_error("Input Error", "Please select an encrypted file")
            return

        if not self.key_var.get():
            MessageHelper.show_error("Input Error", "Please select a key file")
            return

        if not self.output_var.get():
            MessageHelper.show_error("Input Error", "Please specify output file")
            return

        # Run decryption in background
        self.app.update_status("Decrypting file...", "info")
        self.decrypt_btn.configure(state="disabled")

        def do_decrypt():
            try:
                input_file = self.input_var.get()
                output_file = self.output_var.get()
                key_file = self.key_var.get()
                algorithm = self.algorithm_var.get()

                # Load key
                if algorithm == "fernet":
                    key = FernetEncryptor.load_key(key_file)
                    FernetEncryptor.decrypt_file(input_file, output_file, key)
                elif algorithm == "aes256":
                    key = AESEncryptor.load_key(key_file)
                    AESEncryptor.decrypt_file(input_file, output_file, key)

                self.app.update_status(
                    f"✓ File decrypted successfully: {output_file}", "success"
                )
                MessageHelper.show_success(
                    "Success", f"File decrypted successfully!\nOutput: {output_file}"
                )

            except Exception as e:
                self.app.update_status(f"Decryption failed: {str(e)}", "error")
                MessageHelper.show_error("Decryption Error", str(e))
            finally:
                self.decrypt_btn.configure(state="normal")

        ThreadHelper.run_in_thread(do_decrypt)

    def _clear_fields(self):
        """Clear all input fields."""
        self.input_var.set("")
        self.key_var.set("")
        self.output_var.set("")
        self.input_info_label.configure(text="")
        self.app.update_status("Ready", "info")
