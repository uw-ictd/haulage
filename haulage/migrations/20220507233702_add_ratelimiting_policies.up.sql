-- Create tables for managing ratelimit policies

-- Enumerates the kinds of supported link policies
CREATE TABLE IF NOT EXISTS "link_policy_kinds" (
  "id" INT NOT NULL,
  "name" varchar(100) UNIQUE NOT NULL,
  PRIMARY KEY ("id")
);
INSERT INTO "link_policy_kinds" ("id", "name")
VALUES
(1, 'unlimited'),
(2, 'block'),
(3, 'token_bucket');

-- Fully defined ratelimiting policies
CREATE TABLE IF NOT EXISTS "access_policies" (
  "id" INT GENERATED ALWAYS AS IDENTITY,
  "name" varchar(100) UNIQUE NOT NULL,
  "local_ul_policy_kind" INT NOT NULL DEFAULT 1,
  "local_ul_policy_parameters" jsonb NOT NULL DEFAULT '{}',
  "local_dl_policy_kind" INT NOT NULL DEFAULT 1,
  "local_dl_policy_parameters" jsonb NOT NULL DEFAULT '{}',
  "backhaul_ul_policy_kind" INT NOT NULL DEFAULT 1,
  "backhaul_ul_policy_parameters" jsonb NOT NULL DEFAULT '{}',
  "backhaul_dl_policy_kind" INT NOT NULL DEFAULT 1,
  "backhaul_dl_policy_parameters" jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY ("id"),
  CONSTRAINT fk_local_ul_policy FOREIGN KEY ("local_ul_policy_kind") REFERENCES "link_policy_kinds" ("id"),
  CONSTRAINT fk_local_dl_policy FOREIGN KEY ("local_dl_policy_kind") REFERENCES "link_policy_kinds" ("id"),
  CONSTRAINT fk_backhaul_ul_policy FOREIGN KEY ("backhaul_ul_policy_kind") REFERENCES "link_policy_kinds" ("id"),
  CONSTRAINT fk_backhaul_dl_policy FOREIGN KEY ("backhaul_dl_policy_kind") REFERENCES "link_policy_kinds" ("id")
);

INSERT INTO "access_policies"
("name", "local_ul_policy_kind", "local_dl_policy_kind", "backhaul_ul_policy_kind", "backhaul_dl_policy_kind")
VALUES
('Unlimited', 1, 1, 1, 1),
('Local Only', 1, 1, 2, 2);

INSERT INTO "access_policies"
("name", "local_ul_policy_kind", "local_dl_policy_kind", "local_ul_policy_parameters", "local_dl_policy_parameters",
 "backhaul_ul_policy_kind", "backhaul_dl_policy_kind", "backhaul_ul_policy_parameters", "backhaul_dl_policy_parameters")
VALUES
('Limited Backhaul', 1, 1, '{}', '{}',
 3, 3, '{"rate_kibps": 100}', '{"rate_kibps": 100}');

-- Add columns for the access policies applied to each subscriber when they
-- are in different business-logic conditions. Each subscriber should have a
-- uniquely mapped policy for each condition, so the schema keeps the policy
-- mappings in the subscribers table for now.
ALTER TABLE "subscribers"
ADD COLUMN "zero_balance_policy" INT,
ADD COLUMN "positive_balance_policy" INT;

UPDATE "subscribers"
SET "zero_balance_policy" = "access_policies"."id"
FROM "access_policies"
WHERE "access_policies"."name"='Local Only';

UPDATE "subscribers"
SET "positive_balance_policy" = "access_policies"."id"
FROM "access_policies"
WHERE "access_policies"."name"='Unlimited';

ALTER TABLE "subscribers"
ALTER COLUMN "zero_balance_policy" SET NOT NULL,
ALTER COLUMN "positive_balance_policy" SET NOT NULL;

ALTER TABLE "subscribers"
ADD CONSTRAINT "fk_zero_balance_policy"
FOREIGN KEY ("zero_balance_policy")
REFERENCES "access_policies" ("id");

ALTER TABLE "subscribers"
ADD CONSTRAINT "fk_positive_balance_policy"
FOREIGN KEY ("positive_balance_policy")
REFERENCES "access_policies" ("id");
