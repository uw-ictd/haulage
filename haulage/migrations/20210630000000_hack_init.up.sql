-- This migration is intentionally hacky to fix a nasty deployment issue
-- encountered in the field.

-- Specifically, right now against best practices both haulage and the colte
-- billing suite have knowlege of the sql table schema in a shared database, and
-- manage it through their respective migration engines. In the original version
-- of this migration (commented below) the currencies table was created.
-- Unfortunately the currencies table is not important for haulage, and was
-- moved to be managed by the colte migration engine. The crucial mistake is
-- that the table was not renamed at that time, meaning now both migration
-- engines were attempting to manage the currencies table, and both projects had
-- releases made. While the final state of both projects does not conflict, it
-- is possible for one projects migrations to be in a different intermediate
-- state than the other, and actually conflict : /

-- 20210629184727_init.up.sql

-- CREATE TABLE "currencies" (
--   "id" smallint GENERATED ALWAYS AS IDENTITY,
--   "code" char(3) NOT NULL,
--   "name" varchar(32) NOT NULL,
--   "symbol" varchar(8) NOT NULL,
--   PRIMARY KEY ("id")
-- );
-- CREATE UNIQUE INDEX "currencies_code_idx" ON currencies("code");

-- CREATE TABLE "subscribers" (
--   "internal_uid" INT GENERATED ALWAYS AS IDENTITY,
--   "imsi" varchar(16) NOT NULL,
--   "data_balance" bigint DEFAULT '10000000',
--   "balance" decimal(13,4) DEFAULT '0',
--   "currency" smallint NOT NULL,
--   "bridged" boolean DEFAULT 'true',
--   PRIMARY KEY (internal_uid),
--   CONSTRAINT fk_currency FOREIGN KEY(currency) REFERENCES currencies(id)
-- );
-- CREATE UNIQUE INDEX "subscribers_imsi_idx" ON subscribers(imsi);

-- CREATE TABLE "subscriber_history" (
--   "subscriber" INT NOT NULL,
--   "time" timestamptz NOT NULL,
--   "data_balance" bigint NOT NULL,
--   "balance" decimal(13,4) NOT NULL,
--   "bridged" boolean NOT NULL,
--   PRIMARY KEY ("subscriber", "time"),
--   CONSTRAINT fk_subscriber FOREIGN KEY(subscriber) REFERENCES subscribers("internal_uid")
-- );

-- CREATE TABLE "static_ips" (
--   "ip" inet NOT NULL,
--   "imsi" varchar(16) NOT NULL,
--   PRIMARY KEY ("ip"),
--   CONSTRAINT fk_imsi FOREIGN KEY(imsi) REFERENCES subscribers(imsi)
-- );

-- INSERT INTO currencies("name", "code", "symbol")
-- VALUES
--   ('US Dollars', 'USD', '$'),
--   ('Indonesian Rupiah', 'IDR', 'Rp');



CREATE TABLE IF NOT EXISTS "subscribers" (
  "internal_uid" INT GENERATED ALWAYS AS IDENTITY,
  "imsi" varchar(16) NOT NULL,
  "data_balance" bigint DEFAULT '10000000',
  "balance" decimal(13,4) DEFAULT '0',
  "currency" smallint NOT NULL,
  "bridged" boolean DEFAULT 'true',
  PRIMARY KEY (internal_uid)
);
CREATE UNIQUE INDEX IF NOT EXISTS "subscribers_imsi_idx" ON subscribers(imsi);

CREATE TABLE IF NOT EXISTS "subscriber_history" (
  "subscriber" INT NOT NULL,
  "time" timestamptz NOT NULL,
  "data_balance" bigint NOT NULL,
  "balance" decimal(13,4) NOT NULL,
  "bridged" boolean NOT NULL,
  PRIMARY KEY ("subscriber", "time"),
  CONSTRAINT fk_subscriber FOREIGN KEY(subscriber) REFERENCES subscribers("internal_uid")
);

CREATE TABLE IF NOT EXISTS "static_ips" (
  "ip" inet NOT NULL,
  "imsi" varchar(16) NOT NULL,
  PRIMARY KEY ("ip"),
  CONSTRAINT fk_imsi FOREIGN KEY(imsi) REFERENCES subscribers(imsi)
);
