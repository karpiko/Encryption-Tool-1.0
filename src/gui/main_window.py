"""Main GUI window for the encryption tool."""

import customtkinter as ctk
from tkinter import filedialog
import os
from pathlib import Path
import threading

from .styles import *
from .utils import FileDialogHelper, MessageHelper, ThreadHelper, format_file_size
from .encrypt_tab import EncryptTab
from .decrypt_tab import DecryptTab
from .keygen_tab import KeyGenTab


class EncryptionToolApp(ctk.CTk):
    """Main application window."""

    def __init__(self):
        """Initialize the application."""
        super().__init__()

        # Configure window
        self.title("File Encryption Tool - Davenport University")
        self.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.resizable(True, True)

        # Set minimum window size
        self.minsize(800, 600)

        # Configure grid
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Create header
        self._create_header()

        # Create main content area
        self._create_content()

        # Create status bar
        self._create_status_bar()

        # Center window on screen
        self._center_window()

    def _create_header(self):
        """Create header with logo and title."""
        header_frame = ctk.CTkFrame(
            self, fg_color=DAVENPORT_WHITE, corner_radius=0, height=80
        )
        header_frame.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        header_frame.grid_propagate(False)

        # Left side - Logo and title
        left_frame = ctk.CTkFrame(header_frame, fg_color=DAVENPORT_WHITE)
        left_frame.pack(side="left", padx=PADDING, pady=PADDING, fill="both", expand=True)

        # Try to load logo
        logo_path = self._get_logo_path()
        if logo_path and os.path.exists(logo_path):
            try:
                from PIL import Image, ImageTk

                logo_img = Image.open(logo_path).resize((60, 60), Image.Resampling.LANCZOS)
                self.logo_photo = ImageTk.PhotoImage(logo_img)

                logo_label = ctk.CTkLabel(
                    left_frame, image=self.logo_photo, text="", fg_color=DAVENPORT_WHITE
                )
                logo_label.pack(side="left", padx=(0, 15))
            except Exception:
                pass

        # Title and subtitle
        title_frame = ctk.CTkFrame(left_frame, fg_color=DAVENPORT_WHITE)
        title_frame.pack(side="left", fill="both", expand=True)

        title = ctk.CTkLabel(
            title_frame,
            text="File Encryption Tool",
            text_color=DAVENPORT_RED,
            font=TITLE_FONT,
            anchor="w",
        )
        title.pack(anchor="w")

        subtitle = ctk.CTkLabel(
            title_frame,
            text="Davenport University - Secure File Encryption",
            text_color=DAVENPORT_DARK_GRAY,
            font=("Segoe UI", 10),
            anchor="w",
        )
        subtitle.pack(anchor="w")

        # Separator line
        separator = ctk.CTkFrame(self, fg_color=DAVENPORT_RED, height=3)
        separator.grid(row=0, column=0, sticky="ew", padx=0, pady=(80, 0), in_=header_frame)

    def _create_content(self):
        """Create main content area with tabs."""
        # Create tabview
        self.tabview = ctk.CTkTabview(self, corner_radius=10)
        self.tabview.grid(row=1, column=0, sticky="nsew", padx=PADDING, pady=PADDING)

        # Configure tabs
        self.tabview.add("Encrypt")
        self.tabview.add("Decrypt")
        self.tabview.add("Key Generation")

        # Set tab colors
        self.tabview.configure(
            fg_color=BACKGROUND_COLOR,
            segmented_button_fg_color=DAVENPORT_DARK_GRAY,
            segmented_button_selected_color=DAVENPORT_RED,
            segmented_button_selected_hover_color="#A00A24",
            text_color=DAVENPORT_WHITE,
        )

        # Create tab content
        self.encrypt_tab = EncryptTab(self.tabview.tab("Encrypt"), self)
        self.decrypt_tab = DecryptTab(self.tabview.tab("Decrypt"), self)
        self.keygen_tab = KeyGenTab(self.tabview.tab("Key Generation"), self)

    def _create_status_bar(self):
        """Create status bar at the bottom."""
        self.status_bar = ctk.CTkFrame(
            self, fg_color=DAVENPORT_LIGHT_GRAY, height=30, corner_radius=0
        )
        self.status_bar.grid(row=2, column=0, sticky="ew", padx=0, pady=0)
        self.status_bar.grid_propagate(False)

        self.status_label = ctk.CTkLabel(
            self.status_bar,
            text="Ready",
            text_color=DAVENPORT_DARK_GRAY,
            font=STATUS_FONT,
            anchor="w",
        )
        self.status_label.pack(padx=PADDING, pady=5, fill="both", expand=True)

    def update_status(self, message, status_type="info"):
        """
        Update status bar message.

        Args:
            message: Status message
            status_type: Type of status (info, success, error, warning)
        """
        color_map = {
            "info": INFO_COLOR,
            "success": SUCCESS_COLOR,
            "error": ERROR_COLOR,
            "warning": WARNING_COLOR,
        }
        text_color = color_map.get(status_type, INFO_COLOR)

        self.status_label.configure(text=message, text_color=text_color)
        self.update_idletasks()

    def _center_window(self):
        """Center window on screen."""
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def _get_logo_path(self):
        """Get path to logo file."""
        # Try multiple locations
        possible_paths = [
            os.path.join(os.path.dirname(__file__), "..", "..", "assets", "davenport_logo.png"),
            os.path.join(os.path.dirname(__file__), "davenport_logo.png"),
            os.path.expanduser("~/davenport_logo.png"),
        ]

        for path in possible_paths:
            if os.path.exists(path):
                return path
        return None

    def run(self):
        """Run the application."""
        self.mainloop()


def main():
    """Entry point for the GUI application."""
    app = EncryptionToolApp()
    app.run()


if __name__ == "__main__":
    main()
