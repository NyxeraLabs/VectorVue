-- Copyright (c) 2026 NyxeraLabs
-- Author: José María Micoli
-- Licensed under BSL 1.1
-- Change Date: 2033-02-17 → Apache-2.0
--
-- You may:
-- ✔ Study
-- ✔ Modify
-- ✔ Use for internal security testing
--
-- You may NOT:
-- ✘ Offer as a commercial service
-- ✘ Sell derived competing products

-- Phase 0 Sprint 0.1
-- Telemetry capability removal from client API
-- Apply on dev/integration environments after backup validation.

BEGIN;

DROP TABLE IF EXISTS spectrastrike_events CASCADE;
DROP TABLE IF EXISTS spectrastrike_findings CASCADE;
DROP TABLE IF EXISTS spectrastrike_ingest_requests CASCADE;
DROP TABLE IF EXISTS spectrastrike_idempotency CASCADE;
DROP TABLE IF EXISTS client_activity_events CASCADE;

COMMIT;
