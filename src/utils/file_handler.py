"""File handling utilities for encryption/decryption operations."""

import os
from pathlib import Path
from typing import Tuple


class FileHandler:
    """Utility class for file operations in encryption tool."""

    @staticmethod
    def read_file(filepath: str) -> bytes:
        """
        Read a file and return its contents as bytes.

        Args:
            filepath: Path to the file to read

        Returns:
            File contents as bytes

        Raises:
            FileNotFoundError: If file does not exist
            IOError: If file cannot be read
        """
        try:
            with open(filepath, "rb") as f:
                return f.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {filepath}")
        except IOError as e:
            raise IOError(f"Error reading file {filepath}: {e}")

    @staticmethod
    def write_file(filepath: str, data: bytes, overwrite: bool = False) -> None:
        """
        Write bytes to a file.

        Args:
            filepath: Path to the file to write
            data: Bytes to write to file
            overwrite: Whether to overwrite if file exists

        Raises:
            FileExistsError: If file exists and overwrite is False
            IOError: If file cannot be written
        """
        path = Path(filepath)

        # Check if file exists
        if path.exists() and not overwrite:
            raise FileExistsError(
                f"File already exists: {filepath}. Use --overwrite to replace."
            )

        try:
            # Create parent directories if they don't exist
            path.parent.mkdir(parents=True, exist_ok=True)

            with open(filepath, "wb") as f:
                f.write(data)
        except IOError as e:
            raise IOError(f"Error writing to file {filepath}: {e}")

    @staticmethod
    def validate_input_file(filepath: str) -> bool:
        """
        Validate that input file exists and is readable.

        Args:
            filepath: Path to file to validate

        Returns:
            True if valid

        Raises:
            FileNotFoundError: If file doesn't exist
            PermissionError: If file is not readable
        """
        path = Path(filepath)

        if not path.exists():
            raise FileNotFoundError(f"Input file not found: {filepath}")

        if not path.is_file():
            raise ValueError(f"Path is not a file: {filepath}")

        if not os.access(filepath, os.R_OK):
            raise PermissionError(f"No read permission for file: {filepath}")

        return True

    @staticmethod
    def validate_output_path(filepath: str) -> bool:
        """
        Validate that output path is writable.

        Args:
            filepath: Path to validate for writing

        Returns:
            True if valid

        Raises:
            PermissionError: If path is not writable
        """
        path = Path(filepath)
        parent_dir = path.parent

        # If parent directory doesn't exist, check if we can create it
        if not parent_dir.exists():
            try:
                parent_dir.mkdir(parents=True, exist_ok=True)
                return True
            except PermissionError:
                raise PermissionError(f"No write permission for directory: {parent_dir}")

        if not os.access(parent_dir, os.W_OK):
            raise PermissionError(f"No write permission for directory: {parent_dir}")

        return True

    @staticmethod
    def get_file_size(filepath: str) -> int:
        """
        Get file size in bytes.

        Args:
            filepath: Path to file

        Returns:
            File size in bytes

        Raises:
            FileNotFoundError: If file doesn't exist
        """
        try:
            return os.path.getsize(filepath)
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {filepath}")

    @staticmethod
    def format_file_size(size_bytes: int) -> str:
        """
        Format bytes to human-readable format.

        Args:
            size_bytes: Size in bytes

        Returns:
            Formatted string (e.g., "1.5 MB")
        """
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"
