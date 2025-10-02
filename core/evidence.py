"""
core/evidence.py - Evidence collection toolkit

Provides functionality for digital evidence collection during incident response,
including disk imaging, volatile memory dumps, and log extraction.

NOTE: Many operations require elevated privileges and platform-specific tools.
Stubs and demo logic are provided for extension with real tooling (e.g.,
ftkimager, dd, dc3dd, ewfacquire, winpmem, LiME, log collection scripts).
"""
from __future__ import annotations
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional


@dataclass
class CollectionResult:
    collection_id: str
    type: str
    target: str
    output_path: str
    status: str
    started_at: str
    completed_at: Optional[str] = None
    notes: Optional[str] = None


class EvidenceCollector:
    """
    EvidenceCollector orchestrates evidence collection tasks.

    Supported collection types:
    - disk: raw imaging or E01 via external tools
    - memory: volatile memory dump using platform tools
    - logs: OS/application logs collection and archiving
    """

    def __init__(self, output_dir: str = "output/evidence"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def _new_id(self, prefix: str) -> str:
        return f"{prefix}-{datetime.now().strftime('%Y%m%d%H%M%S')}"

    def start_collection(self, ctype: str, target: str) -> CollectionResult:
        ctype = ctype.lower()
        collection_id = self._new_id("COL")
        started_at = datetime.now().isoformat()
        dest_dir = os.path.join(self.output_dir, collection_id)
        os.makedirs(dest_dir, exist_ok=True)

        if ctype == "disk":
            result = self._collect_disk_image(target, dest_dir)
        elif ctype == "memory":
            result = self._collect_memory_dump(target, dest_dir)
        elif ctype == "logs":
            result = self._collect_logs(target, dest_dir)
        else:
            result = CollectionResult(
                collection_id=collection_id,
                type=ctype,
                target=target,
                output_path=dest_dir,
                status="unsupported",
                started_at=started_at,
                notes="Unknown collection type"
            )
        return result

    def _collect_disk_image(self, target: str, dest_dir: str) -> CollectionResult:
        """
        Create a disk image of the target device or file.
        Demo: creates a placeholder file; replace with dd/ewfacquire, etc.
        """
        cid = os.path.basename(dest_dir)
        out_path = os.path.join(dest_dir, "disk_image.dd")
        with open(out_path, "wb") as f:
            f.write(b"DEMO_DISK_IMAGE\n")
        return CollectionResult(
            collection_id=cid, type="disk", target=target,
            output_path=out_path, status="completed", started_at=datetime.now().isoformat(),
            completed_at=datetime.now().isoformat(), notes="Demo disk image created"
        )

    def _collect_memory_dump(self, target: str, dest_dir: str) -> CollectionResult:
        """
        Acquire volatile memory dump.
        Demo: creates a placeholder file; replace with winpmem/LiME invocations.
        """
        cid = os.path.basename(dest_dir)
        out_path = os.path.join(dest_dir, "memdump.raw")
        with open(out_path, "wb") as f:
            f.write(b"DEMO_MEM_DUMP\n")
        return CollectionResult(
            collection_id=cid, type="memory", target=target,
            output_path=out_path, status="completed", started_at=datetime.now().isoformat(),
            completed_at=datetime.now().isoformat(), notes="Demo memory dump created"
        )

    def _collect_logs(self, target: str, dest_dir: str) -> CollectionResult:
        """
        Collect system/application logs and archive them.
        Demo: copies sample logs if present, else creates demo log.
        """
        cid = os.path.basename(dest_dir)
        logs_dir = os.path.join(dest_dir, "logs")
        os.makedirs(logs_dir, exist_ok=True)
        sample_log = os.path.join(logs_dir, "system.log")
        with open(sample_log, "w", encoding="utf-8") as f:
            f.write("Demo log line\n")
        return CollectionResult(
            collection_id=cid, type="logs", target=target,
            output_path=logs_dir, status="completed", started_at=datetime.now().isoformat(),
            completed_at=datetime.now().isoformat(), notes="Demo logs collected"
        )


if __name__ == "__main__":
    collector = EvidenceCollector()
    print(collector.start_collection("disk", "/dev/sda"))
    print(collector.start_collection("memory", "host:local"))
    print(collector.start_collection("logs", "/var/log"))
