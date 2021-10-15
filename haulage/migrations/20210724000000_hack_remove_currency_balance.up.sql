-- As part of fixing the currencies table conflict with CoLTE, this migration
-- drops the relevant columns from the schema only if they exist. It does not
-- drop the currencies table, which may be operated by CoLTE rather than haulage
-- if the CoLTE migrations are current at the point this migration is run.

-- 20210723202906_remove_currency_balance.up
-- ALTER TABLE "subscriber_history"
-- DROP COLUMN "balance";

-- ALTER TABLE "subscribers"
-- DROP CONSTRAINT "fk_currency";

-- ALTER TABLE "subscribers"
-- DROP COLUMN "currency";

-- ALTER TABLE "subscribers"
-- DROP COLUMN "balance";

-- DROP INDEX "currencies_code_idx";
-- DROP TABLE "currencies";

ALTER TABLE "subscriber_history"
DROP COLUMN IF EXISTS "balance";

ALTER TABLE "subscribers"
DROP CONSTRAINT IF EXISTS "fk_currency";

ALTER TABLE "subscribers"
DROP COLUMN IF EXISTS "currency";

ALTER TABLE "subscribers"
DROP COLUMN IF EXISTS "balance";
