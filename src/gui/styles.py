"""Styling and theme configuration for the GUI."""

# Davenport University Colors
DAVENPORT_RED = "#C8102E"
DAVENPORT_BLACK = "#1F1F1F"
DAVENPORT_WHITE = "#FFFFFF"
DAVENPORT_LIGHT_GRAY = "#F5F5F5"
DAVENPORT_DARK_GRAY = "#3E3E3E"

# UI Colors
SUCCESS_COLOR = "#2ECC71"
ERROR_COLOR = "#E74C3C"
WARNING_COLOR = "#F39C12"
INFO_COLOR = "#3498DB"
BACKGROUND_COLOR = "#F8F9FA"
TEXT_COLOR = "#2C3E50"

# Font Settings
TITLE_FONT = ("Segoe UI", 24, "bold")
SUBTITLE_FONT = ("Segoe UI", 14, "bold")
LABEL_FONT = ("Segoe UI", 11)
BUTTON_FONT = ("Segoe UI", 11, "bold")
STATUS_FONT = ("Segoe UI", 10)

# Size Settings
WINDOW_WIDTH = 1000
WINDOW_HEIGHT = 700
PADDING = 20
BUTTON_HEIGHT = 40
INPUT_HEIGHT = 35

# Theme settings for customtkinter
THEME_CONFIG = {
    "fg_color": BACKGROUND_COLOR,
    "text_color": TEXT_COLOR,
}

BUTTON_CONFIG = {
    "fg_color": DAVENPORT_RED,
    "text_color": DAVENPORT_WHITE,
    "hover_color": "#A00A24",
    "font": BUTTON_FONT,
    "height": BUTTON_HEIGHT,
}

BUTTON_SECONDARY_CONFIG = {
    "fg_color": DAVENPORT_DARK_GRAY,
    "text_color": DAVENPORT_WHITE,
    "hover_color": "#555555",
    "font": BUTTON_FONT,
    "height": BUTTON_HEIGHT,
}

ENTRY_CONFIG = {
    "fg_color": DAVENPORT_WHITE,
    "text_color": TEXT_COLOR,
    "border_color": "#CCCCCC",
    "border_width": 1,
    "font": LABEL_FONT,
    "height": INPUT_HEIGHT,
}

LABEL_CONFIG = {
    "text_color": TEXT_COLOR,
    "font": LABEL_FONT,
}

LABEL_TITLE_CONFIG = {
    "text_color": DAVENPORT_RED,
    "font": SUBTITLE_FONT,
}
