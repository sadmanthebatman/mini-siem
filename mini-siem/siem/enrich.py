"""
enrich.py - Add context to normalized events.

A raw alert says "203.0.113.45 failed 25 logins". An enriched alert says
"203.0.113.45 (Russia, known-malicious, never seen before) failed 25 logins
against a CROWN JEWEL host, targeting a privileged account."

The second one is triageable in ten seconds. The first one needs an analyst
to open four browser tabs. Enrichment is where SIEM value is actually created.

All enrichment sources here are OFFLINE files so the pipeline is reproducible
and testable in CI. Swap in live MaxMind/MISP/AbuseIPDB lookups by editing
the loaders only.
"""
from __future__ import annotations

import csv
import ipaddress
import json
from datetime import datetime
from pathlib import Path

import yaml

from .models import Event

PRIVATE_NETS = [ipaddress.ip_network(n) for n in
                ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128")]


def is_internal(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in PRIVATE_NETS)


class Enricher:
    def __init__(self, config_dir: str = "config"):
        self.cfg = Path(config_dir)
        self.geo = self._load_geo()
        self.intel = self._load_intel()
        self.assets = self._load_yaml("assets.yml", {})
        self.identities = self._load_yaml("identities.yml", {})
        # Baseline state for first-seen detection. In production this lives in
        # a database that persists across runs; a dict is fine for a lab.
        self.seen_ips: set[str] = set()
        self.seen_user_ip: set[tuple] = set()
        self.seen_user_host: set[tuple] = set()

    # ---------------- loaders ----------------
    def _load_yaml(self, name: str, default):
        path = self.cfg / name
        if not path.exists():
            return default
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or default

    def _load_geo(self) -> list[tuple]:
        """Minimal offline GeoIP: CIDR -> (country, asn_org). Replace with MaxMind in prod."""
        path = self.cfg / "geoip.csv"
        if not path.exists():
            return []
        rows = []
        with open(path, encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                try:
                    rows.append((ipaddress.ip_network(row["network"]), row["country"],
                                 row["country_code"], row["asn_org"]))
                except ValueError:
                    continue
        return rows

    def _load_intel(self) -> dict:
        """Threat intel indicators: ip -> {source, category, confidence}."""
        path = self.cfg / "threat_intel.json"
        if not path.exists():
            return {}
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    # ---------------- lookups ----------------
    def geo_lookup(self, ip: str) -> dict:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {}
        for net, country, cc, asn in self.geo:
            if addr in net:
                return {"source.geo.country_name": country,
                        "source.geo.country_iso_code": cc,
                        "source.as.organization.name": asn}
        return {}

    def asset_lookup(self, host: str | None) -> dict:
        if not host:
            return {}
        a = self.assets.get(host)
        if not a:
            return {}
        return {"host.criticality": a.get("criticality", "medium"),
                "host.role": a.get("role", "unknown"),
                "host.environment": a.get("environment", "production"),
                "host.owner": a.get("owner", "unassigned")}

    def identity_lookup(self, user: str | None) -> dict:
        if not user:
            return {}
        i = self.identities.get(user, {})
        privileged = i.get("privileged", user in ("root", "Administrator", "admin"))
        return {"user.privileged": privileged,
                "user.type": i.get("type", "unknown"),
                "user.department": i.get("department"),
                "user.enabled": i.get("enabled", True)}

    # ---------------- main ----------------
    def enrich(self, event: Event) -> Event:
        ip = event.get("source.ip")
        user = event.get("user.name")
        host = event.get("host.name")

        if ip:
            internal = is_internal(ip)
            event["source.internal"] = internal
            if not internal:
                event.update(self.geo_lookup(ip))
                hit = self.intel.get(ip)
                if hit:
                    event["threat.indicator.matched"] = True
                    event["threat.indicator.source"] = hit.get("source")
                    event["threat.indicator.category"] = hit.get("category")
                    event["threat.indicator.confidence"] = hit.get("confidence", 50)
            # first-seen flags: novelty is a strong weak-signal
            event["source.first_seen"] = ip not in self.seen_ips
            self.seen_ips.add(ip)

        event.update(self.asset_lookup(host))
        event.update(self.identity_lookup(user))

        if user and ip:
            key = (user, ip)
            event["user.new_source_ip"] = key not in self.seen_user_ip
            self.seen_user_ip.add(key)
        if user and host:
            key = (user, host)
            event["user.new_host"] = key not in self.seen_user_host
            self.seen_user_host.add(key)

        # Business-hours flag drives "unusual time" rules
        ts: datetime = event["@timestamp"]
        event["event.business_hours"] = 8 <= ts.hour < 19 and ts.weekday() < 5
        return event

    def enrich_all(self, events: list[Event]) -> list[Event]:
        # Chronological order matters: first-seen must be computed in time order.
        return [self.enrich(e) for e in sorted(events, key=lambda e: e["@timestamp"])]

    def context_for(self, event: Event) -> dict:
        """Compact context snapshot attached to alerts for analyst triage."""
        keys = ["source.geo.country_name", "source.as.organization.name", "source.internal",
                "threat.indicator.source", "threat.indicator.category",
                "host.criticality", "host.role", "user.privileged", "user.type"]
        return {k: event.get(k) for k in keys if event.get(k) is not None}
