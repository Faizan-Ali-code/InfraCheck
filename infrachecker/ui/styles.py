"""Colours, fonts and style sheets of the JavaFX dashboard (``InfraCheckerFxApp``), translated to Qt style sheets."""
from __future__ import annotations

WINDOW_BACKGROUND = "#f4f4f4"  # JavaFX Modena root background

HEADER = ("QFrame#header { background-color: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0, "
          "stop: 0 #e0f2fe, stop: 1 #f8fafc); }")
CARD = "QFrame#card { background-color: #f8fafc; border: 1px solid #cbd5e1; border-radius: 16px; }"
TILE = "QFrame#tile { background-color: white; border: 1px solid #e2e8f0; border-radius: 12px; }"

TITLE = "font-size: 28px; font-weight: bold; color: #0f172a;"
SUBTITLE = "font-size: 14px; color: #475569;"
AUTHOR = "font-size: 12px; color: #64748b;"
SECTION_TITLE = "font-size: 16px; font-weight: bold; color: #0f172a;"
FIELD_LABEL = "font-size: 13px; font-weight: bold; color: #334155;"
PERCENT = "font-size: 14px; font-weight: bold;"
TILE_LABEL = "font-size: 12px; color: #64748b;"
TILE_VALUE = "font-size: 18px; font-weight: bold; color: #0f172a;"
TILE_HINT = "font-size: 11px; color: #94a3b8;"

UPDATE_HEADLINE = "font-size: 14px; font-weight: bold; color: #0f172a;"
UPDATE_FIELD = "font-size: 12px; color: #1e293b;"
UPDATE_NOTES_TITLE = "font-size: 13px; font-weight: bold; color: #0f172a;"
UPDATE_FOOTER = "color: #475569;"
DIALOG_HEADER = ("QFrame#dialogHeader { background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, "
                 "stop: 0 #f4f4f4, stop: 1 #fdfdfd); border-bottom: 1px solid #c8c8c8; }")
DIALOG_HEADER_TEXT = "font-size: 14px;"
MESSAGE_BOX = "QLabel#qt_msgbox_label { font-size: 14px; }"

PROGRESS_BAR = (
    "QProgressBar { background-color: white; border: 1px solid #b5b5b5; border-radius: 3px; "
    "min-height: 16px; max-height: 16px; }"
    "QProgressBar::chunk { background-color: #0096c9; border-radius: 2px; margin: 1px; }")

URL_TABLE = (
    "QTableView { background-color: white; alternate-background-color: #f9f9f9; "
    "selection-background-color: #0096c9; selection-color: white; }")

LOG_FONT_FAMILY = "Consolas"
LOG_FONT_PIXELS = 12


def _rgba(hex_colour: str, alpha: float) -> str:
    red, green, blue = (int(hex_colour[i:i + 2], 16) for i in (1, 3, 5))
    return f"rgba({red}, {green}, {blue}, {alpha})"


def button(background: str, foreground: str) -> str:
    """Flat bold button; disabled buttons are drawn at 40% opacity like JavaFX."""
    return (f"QPushButton {{ background-color: {background}; color: {foreground}; font-weight: bold; "
            f"border: none; border-radius: 3px; padding: 4px 8px; }}"
            f"QPushButton:disabled {{ background-color: {_rgba(background, 0.4)}; "
            f"color: {_rgba(foreground, 0.4)}; }}")


PRIMARY_BUTTON = button("#2563eb", "#ffffff")
DANGER_BUTTON = button("#dc2626", "#ffffff")
SECONDARY_BUTTON = button("#e2e8f0", "#0f172a")
