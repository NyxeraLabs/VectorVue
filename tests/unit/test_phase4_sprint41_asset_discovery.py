"""Phase 4 Sprint 4.1 tests for ASM asset discovery engine."""

from __future__ import annotations

import unittest

from services.asm_asset_discovery import AssetDiscoveryService


class AssetDiscoveryServiceTests(unittest.TestCase):
    def test_asset_deduplication_validation(self) -> None:
        svc = AssetDiscoveryService()
        tenant = "tenant-a"

        svc.domain_discovery(
            tenant_id=tenant,
            root_domain="example.com",
            discovered_hosts=["api.example.com", "www.example.com"],
        )
        svc.subdomain_bruteforce(
            tenant_id=tenant,
            root_domain="example.com",
            wordlist=["api", "admin"],
        )
        svc.ingest_certificate_transparency(
            tenant_id=tenant,
            entries=[
                {
                    "common_name": "api.example.com",
                    "sans": ["*.example.com", "www.example.com"],
                    "issuer": "Let's Encrypt",
                }
            ],
        )

        assets = svc.list_assets(tenant_id=tenant)
        names = sorted([row.name for row in assets])
        self.assertEqual(names.count("api.example.com"), 1)
        self.assertEqual(names.count("www.example.com"), 1)
        self.assertIn("admin.example.com", names)

    def test_dns_normalization(self) -> None:
        svc = AssetDiscoveryService()
        normalized = svc.normalize_dns_record(
            {"type": " a ", "name": "API.EXAMPLE.COM.", "value": " 203.0.113.10. ", "ttl": "60"}
        )
        self.assertEqual(
            normalized,
            {"type": "A", "name": "api.example.com", "value": "203.0.113.10", "ttl": 60},
        )

    def test_cloud_ingestion_owner_tag_and_criticality(self) -> None:
        svc = AssetDiscoveryService()
        row = svc.ingest_cloud_metadata_aws(
            tenant_id="tenant-a",
            instance={
                "instance_id": "i-prod-auth-001",
                "private_ip": "10.0.0.10",
                "region": "us-east-1",
                "vpc_id": "vpc-1",
                "account_id": "123456789012",
            },
        )
        self.assertEqual(row.asn, 64512)
        tagged = svc.tag_asset_owner(asset_id=row.asset_id, owner_tag="security")
        classified = svc.classify_asset_criticality(asset_id=tagged.asset_id)
        self.assertIn(classified.criticality, {"high", "critical"})


if __name__ == "__main__":
    unittest.main()

