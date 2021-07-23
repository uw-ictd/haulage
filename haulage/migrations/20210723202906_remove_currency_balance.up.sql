ALTER TABLE "subscriber_history"
DROP COLUMN "balance";

ALTER TABLE "subscribers"
DROP CONSTRAINT "fk_currency";

ALTER TABLE "subscribers"
DROP COLUMN "currency";

ALTER TABLE "subscribers"
DROP COLUMN "balance";

DROP INDEX "currencies_code_idx";
DROP TABLE "currencies";
