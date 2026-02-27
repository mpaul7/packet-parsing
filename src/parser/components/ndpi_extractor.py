from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Dict, Any, Iterable

import pandas as pd

from .base_extractor import BaseExtractor


def _run_ndpi_reader(pcap_path: Path) -> str:
    """
    Run ndpiReader -i <pcap> -k <tmpfile> -K json and return the JSON file contents.
    ndpiReader writes one JSON object per line to the path given by -k.
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, prefix="ndpi_"
    ) as f:
        json_path = Path(f.name)

    try:
        result = subprocess.run(
            [
                "ndpiReader",
                "-i",
                str(pcap_path),
                "-k",
                str(json_path),
                "-K",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=3600,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"ndpiReader failed with code {result.returncode}: "
                f"{result.stderr or result.stdout}"
            )
        return json_path.read_text(encoding="utf-8", errors="replace")
    finally:
        try:
            json_path.unlink()
        except OSError:
            pass


def _parse_json_lines(text: str) -> Iterable[Dict[str, Any]]:
    """Yield parsed JSON objects from ndpiReader output (one JSON per line)."""
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue
def _normalize_proto(value: Any) -> int:
    """Convert nDPI proto field (name or number) to a numeric L4 protocol."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        v = value.strip().upper()
        if v.isdigit():
            try:
                return int(v)
            except ValueError:
                pass
        mapping = {
            "TCP": 6,
            "UDP": 17,
            "ICMP": 1,
        }
        if v in mapping:
            return mapping[v]
    # Fallback for unknown/unsupported values
    return 0

def _extract_row(data: dict) -> dict:
    """
    Extract 5-tuple, first_timestamp_ms, JA3, JA4 from nDPI JSON record.
    """
    ndpi = data.get("ndpi") or {}
    tls = ndpi.get("tls") or {}
    return {
        "sip": data.get("src_ip"),
        "dip": data.get("dest_ip"),
        "sport": data.get("src_port"),
        "dport": data.get("dst_port"),
        "protocol": _normalize_proto(data.get("proto")),
        "first_timestamp_ms": data.get("first_seen"),
        "ja3": tls.get("ja3s") or tls.get("ja3"),
        "ja4": tls.get("ja4"),
    }


class NDPIExtractor(BaseExtractor):
    """Extracts packet features using ndpiReader."""

    def extract(self, pcap_file: str) -> pd.DataFrame:
        pcap_path = Path(pcap_file)
        json_content = _run_ndpi_reader(pcap_path)
        records = [_extract_row(obj) for obj in _parse_json_lines(json_content)]
        return pd.DataFrame.from_records(records)

