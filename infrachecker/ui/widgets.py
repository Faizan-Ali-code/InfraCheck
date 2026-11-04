"""Building blocks of the dashboard: cards, stat tiles, the URL status table and the log pane."""
from __future__ import annotations

from importlib import resources

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPersistentModelIndex, Qt
from PySide6.QtGui import QFont, QPainter, QPixmap, QTextCursor
from PySide6.QtWidgets import (QAbstractItemView, QFrame, QHBoxLayout, QHeaderView, QLabel, QPlainTextEdit,
                               QTableView, QVBoxLayout)

from ..log import log
from . import styles
from .state import UrlRow

LOGO_RESOURCE = "InfraCheckerLogo.png"
TABLE_PLACEHOLDER = "No URLs queued yet."
TABLE_COLUMNS = ("Thread", "URL", "Status")
TABLE_COLUMN_WIDTHS = (140, 520, 180)
TABLE_ROW_HEIGHT = 28
LOG_MAX_CHARS = 200_000
LOG_TRIM_EXTRA = 20_000

_logo: QPixmap | None = None


def load_logo() -> QPixmap | None:
    """The bundled logo, loaded once; ``None`` (with a warning) when missing or unreadable."""
    global _logo
    if _logo is None:
        try:
            data = resources.files("infrachecker.resources").joinpath(LOGO_RESOURCE).read_bytes()
        except OSError:
            log.warning(f"Logo resource not found: /{LOGO_RESOURCE}")
            return None
        pixmap = QPixmap()
        if not pixmap.loadFromData(data):
            log.warning(f"Unable to load application logo: invalid image data in /{LOGO_RESOURCE}")
            return None
        _logo = pixmap
    return _logo


def styled_label(text: str, style: str, wrap: bool = False) -> QLabel:
    label = QLabel(text)
    label.setStyleSheet(style)
    label.setWordWrap(wrap)
    return label


def section_title(text: str) -> QLabel:
    return styled_label(text, styles.SECTION_TITLE)


class Card(QFrame):
    """Rounded light card (JavaFX VBox with the shared card style) holding a vertical layout."""

    def __init__(self, spacing: int, padding: int = 18) -> None:
        super().__init__()
        self.setObjectName("card")
        self.setStyleSheet(styles.CARD)
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(padding, padding, padding, padding)
        self.body.setSpacing(spacing)


class HeaderBar(QFrame):
    """Gradient header: logo, title, subtitle and author line."""

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("header")
        self.setStyleSheet(styles.HEADER)
        row = QHBoxLayout(self)
        row.setContentsMargins(20, 16, 20, 8)
        row.setSpacing(16)
        logo = load_logo()
        if logo is not None:
            ratio = self.devicePixelRatioF()
            scaled = logo.scaled(int(72 * ratio), int(72 * ratio), Qt.AspectRatioMode.KeepAspectRatio,
                                 Qt.TransformationMode.SmoothTransformation)
            scaled.setDevicePixelRatio(ratio)
            image = QLabel()
            image.setPixmap(scaled)
            row.addWidget(image, 0, Qt.AlignmentFlag.AlignVCenter)
        texts = QVBoxLayout()
        texts.setSpacing(4)
        texts.addWidget(styled_label("InfraChecker", styles.TITLE))
        texts.addWidget(styled_label("Desktop dashboard for web infrastructure security analysis.", styles.SUBTITLE))
        texts.addWidget(styled_label("Developed By: Taskeen Ahmad", styles.AUTHOR))
        row.addLayout(texts)
        row.addStretch(1)


class StatTile(QFrame):
    """White tile with a caption, a large value and a hint."""

    def __init__(self, caption: str, value: str, hint: str) -> None:
        super().__init__()
        self.setObjectName("tile")
        self.setStyleSheet(styles.TILE)
        box = QVBoxLayout(self)
        box.setContentsMargins(10, 10, 10, 10)
        box.setSpacing(4)
        self.caption = styled_label(caption, styles.TILE_LABEL)
        self.value = styled_label(value, styles.TILE_VALUE, wrap=True)
        self.hint = styled_label(hint, styles.TILE_HINT, wrap=True)
        for label in (self.caption, self.value, self.hint):
            box.addWidget(label)
        box.addStretch(1)

    def set_value(self, text: str) -> None:
        self.value.setText(text)


class UrlTableModel(QAbstractTableModel):
    """Rows of the URL Processing Status table, appended in batches by the refresh tick."""

    def __init__(self) -> None:
        super().__init__()
        self._rows: list[UrlRow] = []
        self._positions: dict[str, int] = {}

    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(TABLE_COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return TABLE_COLUMNS[section]
        return None

    def data(self, index: QModelIndex | QPersistentModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole or not index.isValid():
            return None
        row = self._rows[index.row()]
        return (row.thread, row.url, row.status)[index.column()]

    def row_at(self, position: int) -> UrlRow:
        return self._rows[position]

    def append_rows(self, rows: list[UrlRow]) -> None:
        if not rows:
            return
        start = len(self._rows)
        self.beginInsertRows(QModelIndex(), start, start + len(rows) - 1)
        for offset, row in enumerate(rows):
            self._positions[row.thread] = start + offset
            self._rows.append(row)
        self.endInsertRows()

    def refresh_rows(self, rows: list[UrlRow]) -> None:
        """Repaint the status cells of rows already shown (others pick up their status when appended)."""
        positions = [self._positions[row.thread] for row in rows if row.thread in self._positions]
        if positions:
            status = len(TABLE_COLUMNS) - 1
            self.dataChanged.emit(self.index(min(positions), status), self.index(max(positions), status),
                                  [Qt.ItemDataRole.DisplayRole])

    def clear(self) -> None:
        self.beginResetModel()
        self._rows.clear()
        self._positions.clear()
        self.endResetModel()


class UrlTableView(QTableView):
    """Read-only table with fixed 28 px rows, proportional columns and a placeholder when empty."""

    def __init__(self, model: UrlTableModel) -> None:
        super().__init__()
        self.setModel(model)
        self.setStyleSheet(styles.URL_TABLE)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setAlternatingRowColors(True)
        self.setShowGrid(False)
        self.setWordWrap(False)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        rows = self.verticalHeader()
        rows.setVisible(False)
        rows.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        rows.setMinimumSectionSize(TABLE_ROW_HEIGHT)
        rows.setDefaultSectionSize(TABLE_ROW_HEIGHT)
        columns = self.horizontalHeader()
        columns.setStretchLastSection(True)
        columns.setDefaultAlignment(Qt.AlignmentFlag.AlignCenter)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        total = sum(TABLE_COLUMN_WIDTHS)
        width = self.viewport().width()
        for column, preferred in enumerate(TABLE_COLUMN_WIDTHS[:-1]):
            self.setColumnWidth(column, width * preferred // total)

    def paintEvent(self, event) -> None:
        super().paintEvent(event)
        if self.model().rowCount() == 0:
            painter = QPainter(self.viewport())
            painter.drawText(self.viewport().rect(), Qt.AlignmentFlag.AlignCenter, TABLE_PLACEHOLDER)
            painter.end()


class LogView(QPlainTextEdit):
    """Read-only, unwrapped Consolas pane capped at 200,000 characters (oldest text trimmed, plus 20,000)."""

    def __init__(self) -> None:
        super().__init__()
        self.setReadOnly(True)
        self.setUndoRedoEnabled(False)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        font = QFont(styles.LOG_FONT_FAMILY)
        font.setPixelSize(styles.LOG_FONT_PIXELS)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.setFont(font)

    def length(self) -> int:
        return self.document().characterCount() - 1

    def append_text(self, text: str) -> None:
        """Append and keep the view at the bottom-left, like the Java TextArea refresh."""
        if not text:
            return
        before = self.length()
        cursor = QTextCursor(self.document())
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text)
        excess = self.length() - LOG_MAX_CHARS
        if excess > 0:
            cursor.setPosition(0)
            cursor.setPosition(min(before, excess + LOG_TRIM_EXTRA), QTextCursor.MoveMode.KeepAnchor)
            cursor.removeSelectedText()
        self.moveCursor(QTextCursor.MoveOperation.End)
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())
        self.horizontalScrollBar().setValue(0)
