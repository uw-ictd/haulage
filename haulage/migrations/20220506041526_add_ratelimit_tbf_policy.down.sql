-- Add down migration script here

DELETE
FROM "ratelimit_policies"
WHERE "id"=2 AND "name"='token_bucket';
