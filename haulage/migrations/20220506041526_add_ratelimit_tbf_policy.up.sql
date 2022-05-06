-- Add up migration script here

INSERT INTO "ratelimit_policies" ("id", "name")
VALUES
(2, 'token_bucket');
