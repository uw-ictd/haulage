-- Add down migration script here

ALTER TABLE "subscribers"
DROP CONSTRAINT IF EXISTS "fk_dl_limit_policy";

ALTER TABLE "subscribers"
DROP COLUMN IF EXISTS "dl_limit_policy",
DROP COLUMN IF EXISTS "dl_limit_policy_parameters";


ALTER TABLE "subscribers"
DROP CONSTRAINT IF EXISTS "fk_ul_limit_policy";

ALTER TABLE "subscribers"
DROP COLUMN IF EXISTS "ul_limit_policy",
DROP COLUMN IF EXISTS "ul_limit_policy_parameters";

DROP TABLE IF EXISTS "ratelimit_policies";
