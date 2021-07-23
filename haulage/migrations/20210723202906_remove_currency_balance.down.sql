CREATE TABLE "currencies" (
  "id" smallint GENERATED ALWAYS AS IDENTITY,
  "code" char(3) NOT NULL,
  "name" varchar(32) NOT NULL,
  "symbol" varchar(8) NOT NULL,
  PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "currencies_code_idx" ON currencies("code");

INSERT INTO currencies("name", "code", "symbol")
VALUES
  ('US Dollars', 'USD', '$'),
  ('Indonesian Rupiah', 'IDR', 'Rp');

/* Balance information was lost, set arbirarily to -1 */
ALTER TABLE "subscriber_history"
ADD COLUMN "balance" decimal(13,4) NOT NULL DEFAULT -1;

ALTER TABLE "subscriber_history"
ALTER COLUMN "balance" DROP DEFAULT;

ALTER TABLE "subscribers"
ADD COLUMN "currency" smallint;

/* Assign each subscriber arbitrarily to USD */
UPDATE "subscribers"
SET currency = (SELECT id FROM currencies WHERE currencies.code = 'USD');

ALTER TABLE "subscribers"
ALTER COLUMN "currency" SET NOT NULL;

ALTER TABLE "subscribers"
ADD CONSTRAINT fk_currency FOREIGN KEY(currency) REFERENCES currencies(id);

/* Balance information was lost, set arbirarily to -1 */
ALTER TABLE "subscribers"
ADD COLUMN "balance" decimal(13,4) NOT NULL DEFAULT -1;

ALTER TABLE "subscribers"
ALTER COLUMN "balance" DROP DEFAULT;
