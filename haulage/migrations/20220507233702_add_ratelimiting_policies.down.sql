-- Causes data loss! Remove initial ratelimiting policy support from schema.

ALTER TABLE "subscribers"
DROP CONSTRAINT IF EXISTS "fk_zero_balance_policy",
DROP CONSTRAINT IF EXISTS "fk_positive_balance_policy";

ALTER TABLE "subscribers"
DROP COLUMN IF EXISTS "zero_balance_policy",
DROP COLUMN IF EXISTS "positive_balance_policy";

DROP TABLE IF EXISTS "access_policies";

DROP TABLE IF EXISTS "link_policy_kinds";
