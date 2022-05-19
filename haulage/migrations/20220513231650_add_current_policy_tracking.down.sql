-- Remove the column and constraints for the "currently applied" policy. No
-- fundamental data loss since only used to synchronize transient state.

ALTER TABLE "subscribers"
DROP CONSTRAINT IF EXISTS "fk_current_policy";

ALTER TABLE "subscribers"
DROP COLUMN IF EXISTS "current_policy";
