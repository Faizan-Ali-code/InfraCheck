"""Progress events sent by the orchestrator to the GUI (Java interface ``b``)."""
from __future__ import annotations


class ProgressListener:
    """Override what you need; every method is optional. Methods are called from worker threads."""

    def run_started(self, analysis: int, total_urls: int, pool_size: int) -> None:
        pass

    def url_queued(self, thread_name: str, url: str) -> None:
        pass

    def url_started(self, thread_name: str, url: str) -> None:
        pass

    def url_finished(self, thread_name: str, url: str, success: bool) -> None:
        pass

    def heartbeat(self, done: int, total: int, active: int, queued: int, completed_by_pool: int) -> None:
        pass

    def run_finished(self) -> None:
        pass
