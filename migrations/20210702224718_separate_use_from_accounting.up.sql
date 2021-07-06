-- Add up migration script here
CREATE TABLE "subscriber_usage" (
  "subscriber" INT NOT NULL,
  "start_time" timestamptz NOT NULL,
  "end_time" timestamptz NOT NULL,
  "ran_bytes_up" bigint NOT NULL,
  "ran_bytes_down" bigint NOT NULL,
  "wan_bytes_up" bigint NOT NULL,
  "wan_bytes_down" bigint NOT NULL,
  PRIMARY KEY ("subscriber", "start_time"),
  CONSTRAINT fk_subscriber FOREIGN KEY(subscriber) REFERENCES subscribers("internal_uid")
);