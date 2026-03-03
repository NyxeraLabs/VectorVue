-- Copyright (c) 2026 NyxeraLabs
-- Author: Jose Maria Micoli
-- Licensed under BSL 1.1
-- Change Date: 2033-02-17 -> Apache-2.0
--
-- Phase 9 Sprint 9.1
-- Hardening-oriented index optimization (guarded for backwards compatibility).

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'findings' AND column_name = 'tenant_id'
  ) THEN
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_findings_tenant_visibility_id_desc ON findings(tenant_id, approval_status, visibility, id DESC)';
  END IF;
END$$;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'findings' AND column_name = 'created_at'
  ) THEN
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_findings_tenant_created_at_desc ON findings(tenant_id, created_at DESC)';
  END IF;
END$$;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'evidence_items' AND column_name = 'tenant_id'
  ) THEN
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_evidence_items_tenant_finding_approval_id_desc ON evidence_items(tenant_id, finding_id, approval_status, id DESC)';
  END IF;
END$$;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'client_reports' AND column_name = 'tenant_id'
  ) THEN
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_client_reports_tenant_status_id_desc ON client_reports(tenant_id, status, id DESC)';
  END IF;
END$$;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'remediation_tasks' AND column_name = 'tenant_id'
  ) THEN
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_remediation_tasks_tenant_finding_status_id_desc ON remediation_tasks(tenant_id, finding_id, status, id DESC)';
  END IF;
END$$;
