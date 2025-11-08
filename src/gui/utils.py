"""Utility functions for GUI operations."""

import os
import threading
from tkinter import filedialog, messagebox
from pathlib import Path


class FileDialogHelper:
    """Helper class for file dialog operations."""

    @staticmethod
    def select_file(title="Select a file", filetypes=None):
        """
        Open file selection dialog.

        Args:
            title: Dialog title
            filetypes: File type filters

        Returns:
            Selected file path or None
        """
        if filetypes is None:
            filetypes = [("All Files", "*.*")]

        file_path = filedialog.askopenfilename(
            title=title, filetypes=filetypes, initialdir=os.path.expanduser("~")
        )
        return file_path if file_path else None

    @staticmethod
    def select_save_file(title="Save file as", filetypes=None, defaultext=None):
        """
        Open file save dialog.

        Args:
            title: Dialog title
            filetypes: File type filters
            defaultext: Default file extension

        Returns:
            Selected file path or None
        """
        if filetypes is None:
            filetypes = [("All Files", "*.*")]

        file_path = filedialog.asksaveasfilename(
            title=title,
            filetypes=filetypes,
            defaultextension=defaultext,
            initialdir=os.path.expanduser("~"),
        )
        return file_path if file_path else None

    @staticmethod
    def select_directory(title="Select a directory"):
        """
        Open directory selection dialog.

        Args:
            title: Dialog title

        Returns:
            Selected directory path or None
        """
        directory = filedialog.askdirectory(
            title=title, initialdir=os.path.expanduser("~")
        )
        return directory if directory else None


class MessageHelper:
    """Helper class for message dialogs."""

    @staticmethod
    def show_success(title, message):
        """Show success message."""
        messagebox.showinfo(title, message)

    @staticmethod
    def show_error(title, message):
        """Show error message."""
        messagebox.showerror(title, message)

    @staticmethod
    def show_warning(title, message):
        """Show warning message."""
        messagebox.showwarning(title, message)

    @staticmethod
    def show_info(title, message):
        """Show info message."""
        messagebox.showinfo(title, message)

    @staticmethod
    def ask_confirmation(title, message):
        """Ask for confirmation."""
        return messagebox.askyesno(title, message)


class ThreadHelper:
    """Helper class for running operations in background threads."""

    @staticmethod
    def run_in_thread(func, args=(), on_success=None, on_error=None):
        """
        Run a function in a background thread.

        Args:
            func: Function to run
            args: Arguments to pass to function
            on_success: Callback on success
            on_error: Callback on error
        """

        def worker():
            try:
                result = func(*args)
                if on_success:
                    on_success(result)
            except Exception as e:
                if on_error:
                    on_error(str(e))

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        return thread


def format_file_size(size_bytes):
    """Format bytes to human-readable format."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"


def get_file_info(filepath):
    """Get file information."""
    if not os.path.exists(filepath):
        return None

    file_size = os.path.getsize(filepath)
    file_name = os.path.basename(filepath)

    return {"name": file_name, "size": file_size, "size_formatted": format_file_size(file_size)}
