"""Feed aggregator — pull IOCs from MISP, OpenCTI, TAXII feeds."""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional
from urllib import request as urlreq, error

from .ioc_manager import IOCManager

logger = logging.getLogger(__name__)


class FeedAggregator:
    """
    Aggregates threat intelligence from multiple external feeds.
    Supports MISP, OpenCTI REST API, and TAXII 2.1 servers.

    Usage::

        agg = FeedAggregator(ioc_manager=ioc_mgr)
        agg.add_misp_feed("https://misp.corp.com", api_key="key")
        agg.add_taxii_feed("https://cti.example.com/taxii/", collection_id="...")
        count = agg.refresh_all()
    """

    def __init__(self, ioc_manager: IOCManager) -> None:
        self._mgr = ioc_manager
        self._feeds: List[Dict[str, Any]] = []

    def add_misp_feed(self, base_url: str, api_key: str, verify_ssl: bool = True) -> None:
        """Register a MISP instance as a feed source."""
        self._feeds.append({
            "type": "misp",
            "base_url": base_url.rstrip("/"),
            "api_key": api_key,
            "verify_ssl": verify_ssl,
        })

    def add_opencti_feed(
        self, base_url: str, api_key: str, filters: Optional[Dict] = None
    ) -> None:
        """Register an OpenCTI instance as a feed source."""
        self._feeds.append({
            "type": "opencti",
            "base_url": base_url.rstrip("/"),
            "api_key": api_key,
            "filters": filters or {},
        })

    def add_taxii_feed(
        self, discovery_url: str, collection_id: str, username: str = "", password: str = ""
    ) -> None:
        """Register a TAXII 2.1 server as a feed source."""
        self._feeds.append({
            "type": "taxii",
            "discovery_url": discovery_url,
            "collection_id": collection_id,
            "username": username,
            "password": password,
        })

    def add_csv_feed(self, url: str, value_column: str = "indicator", type_column: str = "type") -> None:
        """Register a CSV-format IOC feed."""
        self._feeds.append({
            "type": "csv",
            "url": url,
            "value_column": value_column,
            "type_column": type_column,
        })

    def refresh_all(self) -> int:
        """Refresh all registered feeds. Returns total IOCs ingested."""
        total = 0
        for feed in self._feeds:
            try:
                count = self._refresh_feed(feed)
                total += count
                logger.info("Ingested %d IOCs from %s feed", count, feed["type"])
            except Exception as e:
                logger.error("Feed refresh failed (%s): %s", feed["type"], e)
        return total

    # ------------------------------------------------------------------

    def _refresh_feed(self, feed: Dict[str, Any]) -> int:
        ft = feed["type"]
        if ft == "misp":
            return self._refresh_misp(feed)
        elif ft == "opencti":
            return self._refresh_opencti(feed)
        elif ft == "taxii":
            return self._refresh_taxii(feed)
        elif ft == "csv":
            return self._refresh_csv(feed)
        return 0

    def _refresh_misp(self, feed: Dict[str, Any]) -> int:
        url = f"{feed['base_url']}/attributes/restSearch"
        payload = json.dumps({"returnFormat": "json", "limit": 1000}).encode()
        req = urlreq.Request(
            url,
            data=payload,
            headers={
                "Authorization": feed["api_key"],
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        with urlreq.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())

        iocs = []
        for attr in data.get("response", {}).get("Attribute", []):
            iocs.append({
                "type": attr.get("type", "string"),
                "value": attr.get("value", ""),
                "description": attr.get("comment", ""),
                "severity": "medium",
                "source": "misp",
            })
        return self._mgr.add_bulk(iocs)

    def _refresh_opencti(self, feed: Dict[str, Any]) -> int:
        query = """
        query {
          indicators(first: 500) {
            edges { node { id name pattern description confidence } }
          }
        }
        """
        req = urlreq.Request(
            f"{feed['base_url']}/graphql",
            data=json.dumps({"query": query}).encode(),
            headers={"Authorization": f"Bearer {feed['api_key']}", "Content-Type": "application/json"},
            method="POST",
        )
        with urlreq.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())

        iocs = []
        for edge in data.get("data", {}).get("indicators", {}).get("edges", []):
            node = edge.get("node", {})
            iocs.append({
                "type": "stix",
                "value": node.get("pattern", ""),
                "description": node.get("description", ""),
                "severity": "medium",
                "source": "opencti",
            })
        return self._mgr.add_bulk(iocs)

    def _refresh_taxii(self, feed: Dict[str, Any]) -> int:
        import base64
        collection_url = f"{feed['discovery_url'].rstrip('/')}/collections/{feed['collection_id']}/objects/"
        auth = base64.b64encode(f"{feed['username']}:{feed['password']}".encode()).decode()
        req = urlreq.Request(
            collection_url,
            headers={
                "Authorization": f"Basic {auth}",
                "Accept": "application/taxii+json;version=2.1",
            },
        )
        with urlreq.urlopen(req, timeout=30) as resp:
            bundle = json.loads(resp.read())
        return self._mgr.ingest_from_stix_bundle(bundle)

    def _refresh_csv(self, feed: Dict[str, Any]) -> int:
        import csv, io
        with urlreq.urlopen(feed["url"], timeout=30) as resp:
            content = resp.read().decode("utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(content))
        iocs = []
        for row in reader:
            value = row.get(feed["value_column"], "").strip()
            ioc_type = row.get(feed["type_column"], "string").strip()
            if value:
                iocs.append({"type": ioc_type, "value": value, "source": "csv"})
        return self._mgr.add_bulk(iocs)
