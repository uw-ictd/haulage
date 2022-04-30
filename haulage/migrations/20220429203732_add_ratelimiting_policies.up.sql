-- Add up migration script here

CREATE TABLE IF NOT EXISTS "ratelimit_policies" (
  "id" INT NOT NULL,
  "name" varchar(100) UNIQUE NOT NULL,
  PRIMARY KEY ("id")
);

INSERT INTO "ratelimit_policies" ("id", "name")
VALUES
(1, 'unlimited');

ALTER TABLE "subscribers"
ADD COLUMN "ul_limit_policy" INT NOT NULL DEFAULT 1,
ADD COLUMN "ul_limit_policy_parameters" jsonb NOT NULL DEFAULT '{}';

ALTER TABLE "subscribers"
ADD CONSTRAINT "fk_ul_limit_policy"
FOREIGN KEY ("ul_limit_policy")
REFERENCES "ratelimit_policies" ("id");

ALTER TABLE "subscribers"
ADD COLUMN "dl_limit_policy" INT NOT NULL DEFAULT 1,
ADD COLUMN "dl_limit_policy_parameters" jsonb NOT NULL DEFAULT '{}';

ALTER TABLE "subscribers"
ADD CONSTRAINT "fk_dl_limit_policy"
FOREIGN KEY ("dl_limit_policy")
REFERENCES "ratelimit_policies" ("id");
