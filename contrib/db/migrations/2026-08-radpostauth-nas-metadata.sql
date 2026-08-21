--
-- daloRADIUS / FreeRADIUS radpostauth NAS metadata migration
--
-- Apply this script when upgrading an existing deployment and you want
-- Last Connection Attempts to display NAS information directly from
-- authentication events.
--
-- Fresh installations should also update FreeRADIUS SQL post-auth queries
-- so these fields are populated at insert time.
--

ALTER TABLE radpostauth
  ADD COLUMN IF NOT EXISTS nasipaddress VARCHAR(45) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS calledstationid VARCHAR(64) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS nasidentifier VARCHAR(128) DEFAULT NULL;
