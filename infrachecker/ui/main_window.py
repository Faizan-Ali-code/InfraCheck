"""Desktop dashboard (Java ``ui.InfraCheckerFxApp``) and the GUI entry point.

Scan and version-check threads never touch widgets: progress goes through :class:`RunState`, log text through
:class:`LogQueue` (both drained by a 250 ms timer) and completions through queued Qt signals.
"""
from __future__ import annotations

import os
import re
import sys
import threading
import time

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QCloseEvent, QColor, QIcon, QPalette
from PySide6.QtWidgets import (QApplication, QComboBox, QGridLayout, QHBoxLayout, QLineEdit, QMainWindow,
                               QProgressBar, QPushButton, QSizePolicy, QTabWidget, QVBoxLayout, QWidget)

from .. import VERSION, config, orchestrator, update
from ..config import Analysis
from ..javacompat.strings import java_trim
from ..log import log, setup as setup_logging
from ..persistence import header_store
from ..scanners.headers import finalize
from ..update import UpdateCheckResult, UpdateStatus
from . import dialogs, styles
from .state import LogQueue, RunState, format_elapsed, format_percent, format_throughput
from .widgets import (Card, HeaderBar, LogView, StatTile, UrlTableModel, UrlTableView, load_logo, section_title,
                      styled_label)

ANALYSES = tuple(analysis for analysis in Analysis if analysis is not Analysis.WAF)
REFRESH_MS = 250
ROW_BATCH = 250
STATUS_BATCH = 1000
LOG_BATCH = 200
PROGRESS_STEPS = 1000
LAUNCHER_THREAD = "InfraChecker-FX-Launcher"
VERSION_CHECK_THREAD = "InfraChecker-Version-Check"

TILES = (
    ("Selected Analysis", "-", "Currently selected mode"),
    ("Status", "Idle", "Current run state"),
    ("Total URLs", "0", "Discovered from urls.txt"),
    ("Completed", "0", "Finished worker executions"),
    ("Success", "0", "Completed without exception"),
    ("Failed", "0", "Workers ended with exception"),
    ("Elapsed", "00:00:00", "Run duration"),
    ("Active Threads", "0", "Executor active count"),
    ("Pool Size", "0", "Configured worker pool"),
    ("Queued Tasks", "0", "Pending work items"),
    ("Throughput", "0/min", "Completed URLs per minute"),
    ("Running Threads", "-", "Live worker names"),
)

_JAVA_INT = re.compile(r"[+-]?[0-9]+")


def _proxy_host(text: str) -> str | None:
    return java_trim(text) or None


def _proxy_port(text: str) -> int:
    """Java ``Integer.parseInt(text.trim())``, 0 when blank or invalid."""
    value = java_trim(text)
    if not _JAVA_INT.fullmatch(value):
        return 0
    port = int(value)
    return port if -2**31 <= port < 2**31 else 0


def _count_url_lines(path: str) -> int:
    """Non-blank lines of urls.txt (Java ``Files.readAllLines``: strict UTF-8, fails when the file is missing)."""
    with open(path, encoding="utf-8") as handle:
        return sum(1 for line in handle.read().split("\n") if java_trim(line))


class MainWindow(QMainWindow):
    """Header, Dashboard tab (Controls / URL Processing Status / Dashboard) and Logs tab."""

    _scan_finished = Signal()
    _version_checked = Signal(object, object, bool)

    def __init__(self, logs: LogQueue) -> None:
        super().__init__()
        self._logs = logs
        self._state = RunState()
        self._scan_running = False
        self._stop_requested = False
        self._started_at: float | None = None
        self._version_check_running = False

        self.setWindowTitle(f"InfraChecker {VERSION}")
        logo = load_logo()
        if logo is not None:
            self.setWindowIcon(QIcon(logo))
        palette = self.palette()
        palette.setColor(QPalette.ColorRole.Window, QColor(styles.WINDOW_BACKGROUND))
        self.setPalette(palette)
        self.resize(1800, 980)
        self.setMinimumSize(1600, 900)

        self.analysis_combo = QComboBox()
        for analysis in ANALYSES:
            self.analysis_combo.addItem(analysis.label)
        self.proxy_host = QLineEdit()
        self.proxy_host.setPlaceholderText("Proxy host (optional)")
        self.proxy_port = QLineEdit()
        self.proxy_port.setPlaceholderText("Proxy port")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, PROGRESS_STEPS)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet(styles.PROGRESS_BAR)
        self.progress_label = styled_label("0%", styles.PERCENT)
        self.start_button = QPushButton("Start Analysis")
        self.stop_button = QPushButton("Stop")
        self.open_urls_button = QPushButton("Open urls.txt")
        self.open_results_button = QPushButton("Open Results Folder")
        self.open_input_button = QPushButton("Open Input Folder")
        self.update_button = QPushButton("Check for Updates")
        self.clear_logs_button = QPushButton("Clear Logs")
        self.tiles = {caption: StatTile(caption, value, hint) for caption, value, hint in TILES}
        self.url_model = UrlTableModel()
        self.url_table = UrlTableView(self.url_model)
        self.log_view = LogView()

        self.start_button.clicked.connect(self.start_analysis)
        self.stop_button.clicked.connect(self.stop_analysis)
        self.open_urls_button.clicked.connect(lambda: self._open(config.URLS_FILE, "urls.txt"))
        self.open_results_button.clicked.connect(lambda: self._open(config.RESULTS_DIR, "results folder"))
        self.open_input_button.clicked.connect(lambda: self._open(os.path.dirname(config.URLS_FILE), "input folder"))
        self.update_button.clicked.connect(lambda: self.check_for_updates(manual=True))
        self.clear_logs_button.clicked.connect(self.clear_logs)
        self.stop_button.setEnabled(False)
        self._scan_finished.connect(self._on_scan_finished)
        self._version_checked.connect(self._on_version_checked)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._dashboard_tab(), "Dashboard")
        self.tabs.addTab(self._logs_tab(), "Logs")
        root = QWidget()
        page = QVBoxLayout(root)
        page.setContentsMargins(0, 0, 0, 0)
        page.setSpacing(0)
        page.addWidget(HeaderBar())
        centre = QVBoxLayout()
        centre.setContentsMargins(12, 12, 12, 12)
        centre.addWidget(self.tabs)
        page.addLayout(centre, 1)
        self.setCentralWidget(root)

        self._timer = QTimer(self)
        self._timer.setInterval(REFRESH_MS)
        self._timer.timeout.connect(self._on_tick)
        self._timer.start()

    # ---------------------------------------------------------------- layout

    def _dashboard_tab(self) -> QWidget:
        tab = QWidget()
        columns = QHBoxLayout(tab)
        columns.setContentsMargins(0, 0, 0, 0)
        columns.setSpacing(12)
        for card, stretch in ((self._controls_card(), 20), (self._status_card(), 50), (self._stats_card(), 30)):
            card.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Ignored)
            columns.addWidget(card, stretch)
        return tab

    def _controls_card(self) -> Card:
        card = Card(spacing=16)
        card.setMinimumWidth(300)
        card.body.addWidget(section_title("Controls"))
        form = QGridLayout()
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(10)
        form.setColumnStretch(0, 35)
        form.setColumnStretch(1, 65)
        for row, (caption, field) in enumerate((("Analysis", self.analysis_combo), ("Proxy Host", self.proxy_host),
                                                ("Proxy Port", self.proxy_port))):
            field.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
            form.addWidget(styled_label(caption, styles.FIELD_LABEL), row, 0)
            form.addWidget(field, row, 1)
        card.body.addLayout(form)

        progress = QVBoxLayout()
        progress.setSpacing(8)
        progress.addWidget(section_title("Progress"))
        bar_row = QHBoxLayout()
        bar_row.setSpacing(10)
        bar_row.addWidget(self.progress_bar, 1)
        bar_row.addWidget(self.progress_label)
        progress.addLayout(bar_row)
        card.body.addLayout(progress)

        buttons = QVBoxLayout()
        buttons.setSpacing(10)
        for button, style in ((self.start_button, styles.PRIMARY_BUTTON), (self.stop_button, styles.DANGER_BUTTON),
                              (self.open_urls_button, styles.SECONDARY_BUTTON),
                              (self.open_results_button, styles.SECONDARY_BUTTON),
                              (self.open_input_button, styles.SECONDARY_BUTTON),
                              (self.update_button, styles.SECONDARY_BUTTON),
                              (self.clear_logs_button, styles.SECONDARY_BUTTON)):
            button.setStyleSheet(style)
            buttons.addWidget(button)
        card.body.addLayout(buttons)
        card.body.addStretch(1)
        return card

    def _status_card(self) -> Card:
        card = Card(spacing=10)
        card.body.addWidget(section_title("URL Processing Status"))
        card.body.addWidget(self.url_table, 1)
        return card

    def _stats_card(self) -> Card:
        card = Card(spacing=12)
        card.setMinimumWidth(420)
        card.body.addWidget(section_title("Dashboard"))
        grid = QGridLayout()
        grid.setSpacing(10)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        for position, tile in enumerate(self.tiles.values()):
            tile.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
            grid.addWidget(tile, position // 2, position % 2)
        card.body.addLayout(grid)
        card.body.addStretch(1)
        return card

    def _logs_tab(self) -> QWidget:
        card = Card(spacing=10)
        card.body.addWidget(section_title("Logs"))
        card.body.addWidget(self.log_view, 1)
        return card

    # ---------------------------------------------------------------- lifecycle

    @property
    def scan_running(self) -> bool:
        return self._scan_running

    def start(self) -> None:
        """Show the window maximised, then run the silent startup version check."""
        self.showMaximized()
        self.post_message("GUI initialized successfully.")
        self._refresh_stats()
        self.check_for_updates(manual=False)

    def exit_application(self) -> None:
        """Stop the scan pool and quit (Java ``InfraChecker.a()`` + ``System.exit(0)``)."""
        orchestrator.stop()
        QApplication.quit()

    def closeEvent(self, event: QCloseEvent) -> None:
        event.accept()
        self.exit_application()

    def post_message(self, text: str) -> None:
        """GUI-only message for the Logs tab (not written to the log file). GUI thread only."""
        self._logs.put(text)
        self.log_view.append_text(self._logs.drain(LOG_BATCH))

    def clear_logs(self) -> None:
        self._logs.clear()
        self.log_view.clear()

    # ---------------------------------------------------------------- scan

    def start_analysis(self) -> None:
        if self._scan_running:
            self.post_message("A scan is already running.")
            return
        index = self.analysis_combo.currentIndex()
        if index < 0:
            self.post_message("Please select an analysis option.")
            return
        analysis = ANALYSES[index]
        proxy_host = _proxy_host(self.proxy_host.text())
        proxy_port = _proxy_port(self.proxy_port.text())
        self._reset_run()
        if analysis is Analysis.HEADERS:
            self._clean_previous_header_run()
        self.tiles["Selected Analysis"].set_value(analysis.label)
        self.tiles["Status"].set_value("Running")
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self._scan_running = True
        self._started_at = time.monotonic()
        threading.Thread(target=self._launch, args=(analysis, proxy_host, proxy_port), name=LAUNCHER_THREAD,
                         daemon=True).start()

    def stop_analysis(self) -> None:
        self._stop_requested = True
        orchestrator.stop()
        self.tiles["Status"].set_value("Stopping...")
        self.stop_button.setEnabled(False)
        self.post_message("Scan stop requested.")

    def _clean_previous_header_run(self) -> None:
        try:
            header_store.close(config.sqlite_path_for(orchestrator.current_paths.headers))
            finalize.reset_dedup()
            self.post_message("Cleaned up previous analysis database files.")
        except Exception as exc:
            log.warning(f"Unable to clean up previous database files: {exc}", exc_info=True)

    def _launch(self, analysis: Analysis, proxy_host: str | None, proxy_port: int) -> None:
        """Launcher thread: pre-count urls.txt, run the analysis, then signal the GUI."""
        try:
            self._state.preset_total(_count_url_lines(config.URLS_FILE))
            orchestrator.run_analysis(analysis, proxy_host, proxy_port, self._state)
        except Exception as exc:
            log.error(f"Unable to execute GUI scan: {exc}", exc_info=True)
        finally:
            self._scan_finished.emit()

    def _on_scan_finished(self) -> None:
        self._scan_running = False
        stopped = self._stop_requested
        self.tiles["Status"].set_value("Stopped" if stopped else "Completed")
        self.post_message("Scan stopped." if stopped else "Scan completed.")
        self._drain(None, None, None)
        self._refresh_stats()
        if not stopped:
            self._show_summary()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def _show_summary(self) -> None:
        counters = self._state.counters()
        dialogs.show_info(self, "InfraChecker Summary", "Analysis finished successfully",
                          f"Analysis: {self.tiles['Selected Analysis'].value.text()}\n"
                          f"Total URLs: {counters.total}\nCompleted: {counters.completed}\n"
                          f"Success: {counters.success}\nFailed: {counters.failed}\n"
                          f"Elapsed: {self.tiles['Elapsed'].value.text()}")

    def _reset_run(self) -> None:
        self._state.reset()
        self._logs.clear()
        self.url_model.clear()
        self._started_at = None
        self._stop_requested = False
        self.progress_bar.setValue(0)
        self.progress_label.setText("0%")
        for caption, initial, _ in TILES:
            self.tiles[caption].set_value(initial)
        self.tiles["Status"].set_value("Ready")

    # ---------------------------------------------------------------- refresh

    def _on_tick(self) -> None:
        self._drain(ROW_BATCH, STATUS_BATCH, LOG_BATCH)
        if self._scan_running:
            self._refresh_stats()

    def _drain(self, rows: int | None, statuses: int | None, logs: int | None) -> None:
        self.url_model.append_rows(self._state.take_new_rows(rows))
        self.url_model.refresh_rows(self._state.apply_statuses(statuses))
        self.log_view.append_text(self._logs.drain(logs))

    def _refresh_stats(self) -> None:
        counters = self._state.counters()
        seconds = 0 if self._started_at is None else int(time.monotonic() - self._started_at)
        values = {
            "Total URLs": str(counters.total),
            "Completed": str(counters.completed),
            "Success": str(counters.success),
            "Failed": str(counters.failed),
            "Active Threads": str(counters.active),
            "Pool Size": str(counters.pool_size),
            "Queued Tasks": str(max(0, counters.queued)),
            "Elapsed": format_elapsed(seconds),
            "Throughput": format_throughput(counters.completed, seconds),
            "Running Threads": ", ".join(counters.running) or "-",
        }
        for caption, text in values.items():
            self.tiles[caption].set_value(text)
        steps = counters.completed * PROGRESS_STEPS // counters.total if counters.total else 0
        self.progress_bar.setValue(min(steps, PROGRESS_STEPS))
        self.progress_label.setText(format_percent(counters.completed, counters.total))

    # ---------------------------------------------------------------- desktop and updates

    def _open(self, path: str, what: str) -> None:
        try:
            dialogs.open_path(path)
        except Exception as exc:
            log.warning(f"Unable to open {what}: {exc}", exc_info=True)

    def check_for_updates(self, manual: bool) -> None:
        """Run the version check in the background; ``manual`` (the button) also reports "no update" and errors."""
        if self._version_check_running:
            if manual:
                dialogs.show_info(self, "Version Check", "Version check already running",
                                  "Please wait for the current version check to complete.")
            return
        self._version_check_running = True
        self.update_button.setEnabled(False)
        self.post_message("Checking for InfraChecker updates..." if manual
                          else "Checking for InfraChecker updates in background...")
        threading.Thread(target=self._run_version_check, args=(manual,), name=VERSION_CHECK_THREAD,
                         daemon=True).start()

    def _run_version_check(self, manual: bool) -> None:
        try:
            result = update.check_for_update(VERSION)
        except Exception as exc:
            self._version_checked.emit(None, exc, manual)
        else:
            self._version_checked.emit(result, None, manual)

    def _on_version_checked(self, result: UpdateCheckResult | None, error: Exception | None, manual: bool) -> None:
        self._version_check_running = False
        self.update_button.setEnabled(True)
        if result is None:
            log.warning(f"Unexpected version check failure: {error}", exc_info=error)
            self.post_message(f"Version check failed unexpectedly. {error}")
            if manual:
                dialogs.show_warning(self, "Version Check Failed", "Unable to check application version",
                                     "An unexpected error occurred while checking for updates. "
                                     "Please try again later.")
        elif result.status is UpdateStatus.UPDATE_AVAILABLE:
            self._announce_update(result)
        elif result.status is UpdateStatus.UP_TO_DATE:
            self.post_message(f"InfraChecker is up to date. Current version: {result.current_version}")
            if manual:
                latest = f"\nLatest version: {result.info.latest_version}" if result.info else ""
                dialogs.show_info(self, "No Update Available", "You're already on the latest version",
                                  f"Current version: {result.current_version}{latest}")
        else:
            self.post_message(f"Version check failed. {result.message}")
            if manual:
                dialogs.show_warning(self, "Version Check Failed", "Unable to check application version",
                                     result.message or "")

    def _announce_update(self, result: UpdateCheckResult) -> None:
        info = result.info
        if info is None:
            return
        self.post_message(f"Update available. Current version: {result.current_version}, "
                          f"latest version: {info.latest_version}")
        dialogs.UpdateDialog(result.current_version, info, self, self._open_download, self.exit_application).show()

    def _open_download(self, location: str) -> None:
        try:
            dialogs.open_download_location(location)
        except Exception as exc:
            log.warning(f"Unable to open download location: {exc}", exc_info=True)
            dialogs.show_warning(self, "Unable to Open Download Location",
                                 "The download location could not be opened", str(exc))


def run_gui(argv: list[str]) -> int:
    """Start the dashboard. GUI logging is set up first so every record reaches the Logs tab."""
    logs = LogQueue()
    setup_logging(gui_sink=logs.put)
    app = QApplication.instance()
    if not isinstance(app, QApplication):
        app = QApplication([sys.argv[0], *argv])
    app.setStyle("Fusion")
    app.styleHints().setColorScheme(Qt.ColorScheme.Light)
    window = MainWindow(logs)
    window.start()
    code = app.exec()
    if window.scan_running:
        # Like Java's System.exit(0): do not wait for pool threads still working on URLs.
        os._exit(code)
    return code
