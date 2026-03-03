# Copyright (c) 2026 NyxeraLabs
# Author: José María Micoli
# Licensed under BSL 1.1
# Change Date: 2033-02-17 -> Apache-2.0
#
# You may:
# Study
# Modify
# Use for internal security testing
#
# You may NOT:
# Offer as a commercial service
# Sell derived competing products

"""ASM asset discovery engine (Phase 4 Sprint 4.1)."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any


class AsmDiscoveryError(ValueError):
    """Raised when ASM discovery operations fail."""


@dataclass(frozen=True, slots=True)
class AssetInventory:
    """AssetInventory core table row."""

    asset_id: str
    tenant_id: str
    asset_type: str
    name: str
    fqdn: str | None = None
    ip_address: str | None = None
    asn: int | None = None
    cloud_provider: str | None = None
    cloud_account_id: str | None = None
    owner_tag: str | None = None
    criticality: str = "medium"
    source: str = "unknown"
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.asset_id.strip():
            raise AsmDiscoveryError("asset_id is required")
        if not self.tenant_id.strip():
            raise AsmDiscoveryError("tenant_id is required")
        if not self.asset_type.strip():
            raise AsmDiscoveryError("asset_type is required")
        if not self.name.strip():
            raise AsmDiscoveryError("asset name is required")


def _normalize_domain(value: str) -> str:
    return str(value).strip().lower().rstrip(".")


def _normalize_ip(value: str) -> str:
    return str(ipaddress.ip_address(str(value).strip()))


def _fingerprint(tenant_id: str, fqdn: str | None, ip_address: str | None, name: str) -> str:
    fqdn_part = _normalize_domain(fqdn) if fqdn else ""
    ip_part = _normalize_ip(ip_address) if ip_address else ""
    name_part = str(name).strip().lower()
    return f"{tenant_id}|{fqdn_part}|{ip_part}|{name_part}"


class AssetDiscoveryService:
    """In-memory asset discovery and normalization service."""

    def __init__(self) -> None:
        self._assets: dict[str, AssetInventory] = {}
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"asset-{self._counter:06d}"

    def upsert_asset(
        self,
        *,
        tenant_id: str,
        asset_type: str,
        name: str,
        fqdn: str | None = None,
        ip_address: str | None = None,
        source: str,
        metadata: dict[str, Any] | None = None,
        cloud_provider: str | None = None,
        cloud_account_id: str | None = None,
    ) -> AssetInventory:
        clean_fqdn = _normalize_domain(fqdn) if fqdn else None
        clean_ip = _normalize_ip(ip_address) if ip_address else None
        key = _fingerprint(tenant_id=tenant_id, fqdn=clean_fqdn, ip_address=clean_ip, name=name)
        existing = self._assets.get(key)
        merged_metadata = dict(metadata or {})
        if existing:
            merged = replace(
                existing,
                source=source,
                metadata={**existing.metadata, **merged_metadata},
                cloud_provider=cloud_provider or existing.cloud_provider,
                cloud_account_id=cloud_account_id or existing.cloud_account_id,
            )
            self._assets[key] = merged
            return merged
        row = AssetInventory(
            asset_id=self._next_id(),
            tenant_id=tenant_id,
            asset_type=asset_type,
            name=name,
            fqdn=clean_fqdn,
            ip_address=clean_ip,
            source=source,
            metadata=merged_metadata,
            cloud_provider=cloud_provider,
            cloud_account_id=cloud_account_id,
        )
        self._assets[key] = row
        return row

    def domain_discovery(self, *, tenant_id: str, root_domain: str, discovered_hosts: list[str]) -> list[AssetInventory]:
        root = _normalize_domain(root_domain)
        out: list[AssetInventory] = []
        for host in discovered_hosts:
            fqdn = _normalize_domain(host)
            if not fqdn or not fqdn.endswith(root):
                continue
            out.append(
                self.upsert_asset(
                    tenant_id=tenant_id,
                    asset_type="domain",
                    name=fqdn,
                    fqdn=fqdn,
                    source="domain_discovery",
                )
            )
        return out

    def subdomain_bruteforce(
        self, *, tenant_id: str, root_domain: str, wordlist: list[str]
    ) -> list[AssetInventory]:
        root = _normalize_domain(root_domain)
        out: list[AssetInventory] = []
        for word in wordlist:
            token = str(word).strip().lower()
            if not token:
                continue
            fqdn = f"{token}.{root}"
            out.append(
                self.upsert_asset(
                    tenant_id=tenant_id,
                    asset_type="subdomain",
                    name=fqdn,
                    fqdn=fqdn,
                    source="subdomain_bruteforce",
                )
            )
        return out

    def ingest_ip_range(
        self,
        *,
        tenant_id: str,
        cidr: str,
        max_hosts: int = 256,
    ) -> list[AssetInventory]:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
        hosts = list(network.hosts())[: max(1, int(max_hosts))]
        out: list[AssetInventory] = []
        for ip in hosts:
            out.append(
                self.upsert_asset(
                    tenant_id=tenant_id,
                    asset_type="ip",
                    name=str(ip),
                    ip_address=str(ip),
                    source="ip_range_ingestion",
                    metadata={"cidr": str(network)},
                )
            )
        return out

    def asn_lookup(self, *, ip_address: str) -> int:
        ip = ipaddress.ip_address(ip_address.strip())
        if ip.is_private:
            return 64512
        octets = [int(part) for part in str(ip).split(".")] if ip.version == 4 else [int(ip.packed[0])]
        return 10000 + sum(octets) % 50000

    def ingest_certificate_transparency(
        self, *, tenant_id: str, entries: list[dict[str, Any]]
    ) -> list[AssetInventory]:
        out: list[AssetInventory] = []
        for entry in entries:
            names: list[str] = []
            cn = str(entry.get("common_name", "")).strip()
            if cn:
                names.append(cn)
            sans = entry.get("sans", [])
            if isinstance(sans, list):
                names.extend(str(item).strip() for item in sans if str(item).strip())
            for domain in names:
                clean = _normalize_domain(domain.replace("*.", ""))
                out.append(
                    self.upsert_asset(
                        tenant_id=tenant_id,
                        asset_type="domain",
                        name=clean,
                        fqdn=clean,
                        source="certificate_transparency",
                        metadata={"issuer": str(entry.get("issuer", "")).strip()},
                    )
                )
        return out

    def normalize_dns_record(self, record: dict[str, Any]) -> dict[str, Any]:
        record_type = str(record.get("type", "")).strip().upper()
        name = _normalize_domain(str(record.get("name", "")))
        value = str(record.get("value", "")).strip().lower().rstrip(".")
        ttl_raw = record.get("ttl", 300)
        try:
            ttl = int(ttl_raw)
        except (TypeError, ValueError):
            ttl = 300
        return {
            "type": record_type,
            "name": name,
            "value": value,
            "ttl": max(0, ttl),
        }

    def ingest_cloud_metadata_aws(self, *, tenant_id: str, instance: dict[str, Any]) -> AssetInventory:
        private_ip = str(instance.get("private_ip", "")).strip()
        row = self.upsert_asset(
            tenant_id=tenant_id,
            asset_type="cloud_instance",
            name=str(instance.get("instance_id", "aws-instance")).strip(),
            ip_address=private_ip if private_ip else None,
            source="aws_metadata",
            cloud_provider="aws",
            cloud_account_id=str(instance.get("account_id", "")).strip() or None,
            metadata={
                "region": str(instance.get("region", "")).strip(),
                "vpc_id": str(instance.get("vpc_id", "")).strip(),
            },
        )
        if row.ip_address:
            return self._apply_asn(row)
        return row

    def ingest_cloud_metadata_azure(self, *, tenant_id: str, vm: dict[str, Any]) -> AssetInventory:
        private_ip = str(vm.get("private_ip_address", "")).strip()
        row = self.upsert_asset(
            tenant_id=tenant_id,
            asset_type="cloud_instance",
            name=str(vm.get("vm_id", "azure-vm")).strip(),
            ip_address=private_ip if private_ip else None,
            source="azure_metadata",
            cloud_provider="azure",
            cloud_account_id=str(vm.get("subscription_id", "")).strip() or None,
            metadata={
                "resource_group": str(vm.get("resource_group", "")).strip(),
                "location": str(vm.get("location", "")).strip(),
            },
        )
        if row.ip_address:
            return self._apply_asn(row)
        return row

    def ingest_cloud_metadata_gcp(self, *, tenant_id: str, node: dict[str, Any]) -> AssetInventory:
        private_ip = str(node.get("network_ip", "")).strip()
        row = self.upsert_asset(
            tenant_id=tenant_id,
            asset_type="cloud_instance",
            name=str(node.get("instance_id", "gcp-instance")).strip(),
            ip_address=private_ip if private_ip else None,
            source="gcp_metadata",
            cloud_provider="gcp",
            cloud_account_id=str(node.get("project_id", "")).strip() or None,
            metadata={
                "zone": str(node.get("zone", "")).strip(),
                "network": str(node.get("network", "")).strip(),
            },
        )
        if row.ip_address:
            return self._apply_asn(row)
        return row

    def _apply_asn(self, row: AssetInventory) -> AssetInventory:
        if not row.ip_address:
            return row
        asn = self.asn_lookup(ip_address=row.ip_address)
        key = _fingerprint(row.tenant_id, row.fqdn, row.ip_address, row.name)
        updated = replace(row, asn=asn)
        self._assets[key] = updated
        return updated

    def tag_asset_owner(self, *, asset_id: str, owner_tag: str) -> AssetInventory:
        key, row = self._find_asset(asset_id)
        updated = replace(row, owner_tag=owner_tag.strip() or None)
        self._assets[key] = updated
        return updated

    def classify_asset_criticality(self, *, asset_id: str) -> AssetInventory:
        key, row = self._find_asset(asset_id)
        name = row.name.lower()
        owner = (row.owner_tag or "").lower()
        score = 0
        if row.asset_type in {"cloud_instance", "ip"}:
            score += 1
        if any(token in name for token in ("prod", "payment", "auth", "identity", "core")):
            score += 2
        if owner in {"security", "infra", "platform"}:
            score += 1
        if score >= 4:
            level = "critical"
        elif score >= 3:
            level = "high"
        elif score >= 1:
            level = "medium"
        else:
            level = "low"
        updated = replace(row, criticality=level)
        self._assets[key] = updated
        return updated

    def _find_asset(self, asset_id: str) -> tuple[str, AssetInventory]:
        for key, row in self._assets.items():
            if row.asset_id == asset_id:
                return key, row
        raise AsmDiscoveryError("asset not found")

    def list_assets(self, *, tenant_id: str) -> list[AssetInventory]:
        rows = [row for row in self._assets.values() if row.tenant_id == tenant_id]
        return sorted(rows, key=lambda item: item.asset_id)

