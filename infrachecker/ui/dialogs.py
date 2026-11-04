"""Alerts, the update dialog and desktop helpers (Java ``Alert`` and ``Desktop``)."""
from __future__ import annotations

import os
import re
from typing import Callable

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QCloseEvent, QDesktopServices
from PySide6.QtWidgets import (QDialog, QDialogButtonBox, QFrame, QHBoxLayout, QLabel, QMessageBox,
                               QScrollArea, QStyle, QVBoxLayout, QWidget)

from ..javacompat.strings import java_trim
from ..update import VersionInfo
from . import styles
from .widgets import styled_label

UPDATE_TITLE = "InfraChecker Update Available"
OPEN_DOWNLOAD = "Open Download Page"
LATER = "Later"
CLOSE_APPLICATION = "Close Application"

_URL_WITH_SCHEME = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://.*")


def show_message(parent: QWidget | None, icon: QMessageBox.Icon, title: str, header: str,
                 content: str) -> QMessageBox:
    """Non-blocking application-modal alert with a header line and plain-text content (Java ``Alert.show()``)."""
    box = QMessageBox(icon, title, header, QMessageBox.StandardButton.Ok, parent)
    box.setTextFormat(Qt.TextFormat.PlainText)
    box.setInformativeText(content)
    box.setStyleSheet(styles.MESSAGE_BOX)
    box.setWindowModality(Qt.WindowModality.ApplicationModal)
    box.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
    box.show()
    return box


def show_info(parent: QWidget | None, title: str, header: str, content: str) -> QMessageBox:
    return show_message(parent, QMessageBox.Icon.Information, title, header, content)


def show_warning(parent: QWidget | None, title: str, header: str, content: str) -> QMessageBox:
    return show_message(parent, QMessageBox.Icon.Warning, title, header, content)


def open_path(path: str) -> None:
    """Open a file or folder with its default application (Java ``Desktop.open``)."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"The file: {path} doesn't exist.")
    os.startfile(os.path.abspath(path))


def open_download_location(location: str) -> None:
    """Browse to a URL, or open a local file/folder, given as the version file's download location."""
    target = java_trim(location)
    if not target:
        raise OSError("No download URL was provided in the version file.")
    if not _URL_WITH_SCHEME.fullmatch(target):
        open_path(target)
        return
    url = QUrl(target, QUrl.ParsingMode.TolerantMode)
    if not url.isValid():
        raise OSError(f"Invalid download URL: {target}")
    if not QDesktopServices.openUrl(url):
        raise OSError(f"Unable to open {target}")


def _or_dash(value: str) -> str:
    return java_trim(value) or "-"


class UpdateDialog(QDialog):
    """``InfraChecker Update Available``. A mandatory update cannot be dismissed (ESC and window close are
    ignored): "Open Download Page" keeps it open and "Close Application" exits."""

    def __init__(self, current_version: str, info: VersionInfo, parent: QWidget | None,
                 on_open_download: Callable[[str], None], on_close_application: Callable[[], None]) -> None:
        super().__init__(parent)
        self.mandatory = info.mandatory
        self._download_url = info.download_url
        self._on_open_download = on_open_download
        self.setWindowTitle(UPDATE_TITLE)
        self.setWindowModality(Qt.WindowModality.ApplicationModal)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 10)
        layout.addWidget(self._header("Mandatory InfraChecker update available" if self.mandatory
                                      else "A newer InfraChecker version is available"))
        layout.addWidget(self._content(current_version, info))

        buttons = QDialogButtonBox()
        self.open_button = buttons.addButton(OPEN_DOWNLOAD, QDialogButtonBox.ButtonRole.AcceptRole)
        self.dismiss_button = buttons.addButton(CLOSE_APPLICATION if self.mandatory else LATER,
                                                QDialogButtonBox.ButtonRole.RejectRole)
        self.open_button.setDefault(True)
        self.open_button.clicked.connect(self._open_clicked)
        if self.mandatory:
            self.dismiss_button.clicked.connect(on_close_application)
        else:
            self.dismiss_button.clicked.connect(self.reject)
        button_row = QHBoxLayout()
        button_row.setContentsMargins(10, 0, 10, 0)
        button_row.addWidget(buttons)
        layout.addLayout(button_row)
        self.resize(640, self.sizeHint().height())

    def _header(self, text: str) -> QFrame:
        panel = QFrame()
        panel.setObjectName("dialogHeader")
        panel.setStyleSheet(styles.DIALOG_HEADER)
        row = QHBoxLayout(panel)
        row.setContentsMargins(10, 10, 10, 10)
        row.addWidget(styled_label(text, styles.DIALOG_HEADER_TEXT, wrap=True), 1)
        icon = QLabel()
        icon.setPixmap(self.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxInformation).pixmap(32, 32))
        row.addWidget(icon)
        return panel

    def _content(self, current_version: str, info: VersionInfo) -> QScrollArea:
        body = QWidget()
        column = QVBoxLayout(body)
        column.setContentsMargins(8, 8, 8, 8)
        column.setSpacing(10)
        column.addWidget(styled_label(f"A newer version of {info.application or 'InfraChecker'} is available.",
                                      styles.UPDATE_HEADLINE, wrap=True))
        for caption, value in (("Current Version", current_version),
                               ("Latest Version", info.latest_version),
                               ("Release Date", info.release_date),
                               ("Update Type", "Mandatory" if info.mandatory else "Recommended"),
                               ("Download URL", info.download_url)):
            column.addWidget(styled_label(f"{caption}: {_or_dash(value)}", styles.UPDATE_FIELD, wrap=True))
        column.addWidget(styled_label("Release Notes", styles.UPDATE_NOTES_TITLE))
        notes = QVBoxLayout()
        notes.setSpacing(6)
        for line in [f"• {note}" for note in info.release_notes] or [
                "No release notes were provided in the version file."]:
            notes.addWidget(styled_label(line, "", wrap=True))
        column.addLayout(notes)
        column.addWidget(styled_label(
            "This update is marked as mandatory. Please update before your next run." if info.mandatory
            else "You can continue using the current version, but updating is recommended.",
            styles.UPDATE_FOOTER, wrap=True))
        column.addStretch(1)
        for label in body.findChildren(QLabel):
            label.setTextFormat(Qt.TextFormat.PlainText)

        scroll = QScrollArea()
        scroll.setWidget(body)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setMinimumSize(580, 320)
        return scroll

    def _open_clicked(self) -> None:
        if not self.mandatory:
            self.accept()
        self._on_open_download(self._download_url)

    def reject(self) -> None:
        if not self.mandatory:
            super().reject()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self.mandatory:
            event.ignore()
        else:
            super().closeEvent(event)

