-- Add a column for the access policy currenty applied to each subscriber.
ALTER TABLE "subscribers"
ADD COLUMN "current_policy" INT;

-- For the purposes of the migration, just set each subscriber to local only. On
-- startup haulage will check the current policy against the current business
-- logic rules for which policy should be applied, and update if needed.
UPDATE "subscribers"
SET "current_policy" = "access_policies"."id"
FROM "access_policies"
WHERE "access_policies"."name"='Local Only';

ALTER TABLE "subscribers"
ALTER COLUMN "current_policy" SET NOT NULL;

ALTER TABLE "subscribers"
ADD CONSTRAINT "fk_current_policy"
FOREIGN KEY ("current_policy")
REFERENCES "access_policies" ("id");
