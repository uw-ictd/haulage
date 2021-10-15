/* Balance information was lost, set arbirarily to -1 */
ALTER TABLE "subscriber_history"
ADD COLUMN "balance" decimal(13,4) NOT NULL DEFAULT -1;

ALTER TABLE "subscriber_history"
ALTER COLUMN "balance" DROP DEFAULT;

ALTER TABLE "subscribers"
ADD COLUMN "currency" smallint;

UPDATE "subscribers"
SET currency = 0;

ALTER TABLE "subscribers"
ALTER COLUMN "currency" SET NOT NULL;

/* Balance information was lost, set arbirarily to -1 */
ALTER TABLE "subscribers"
ADD COLUMN "balance" decimal(13,4) NOT NULL DEFAULT -1;

ALTER TABLE "subscribers"
ALTER COLUMN "balance" DROP DEFAULT;
