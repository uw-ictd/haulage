#!/usr/bin/env python3

import argparse
import logging

from pathlib import Path

import MySQLdb
import psycopg2
import psycopg2.errors
import yaml

logging.basicConfig(level=logging.DEBUG)


def read_haulage_config(config_path):
    with open(config_path) as f:
        config_file = yaml.load(f, Loader=yaml.SafeLoader)
        try:
            db_name = config_file["custom"]["dbLocation"]
            db_user = config_file["custom"]["dbUser"]
            db_pass = config_file["custom"]["dbPass"]
        except KeyError as e:
            logging.error(
                "Unable to read database information from config file %s", config_path
            )
            raise e

    return (db_name, db_user, db_pass)


def migrate_subscribers(mysql_conn, pg_conn):
    mysql_cursor = mysql_conn.cursor()
    mysql_cursor.execute("BEGIN")
    pg_cursor = pg_conn.cursor()

    mysql_cursor.execute(
        "select imsi, username, raw_down, raw_up, data_balance, balance, bridged, enabled, admin, msisdn from customers;"
    )
    for row in mysql_cursor:
        if row[6] == 1:
            bridged = True
        else:
            bridged = False

        new_sub_row = [row[0], row[4], bridged]

        try:
            pg_cursor.execute("BEGIN TRANSACTION")
            pg_cursor.execute(
                """
                INSERT INTO subscribers("imsi", "data_balance", "bridged")
                VALUES
                (%s, %s, %s)""",
                new_sub_row,
            )
            logging.debug(
                "Migrating customer -> subscriber source row %s -> new subscriber %s",
                row,
                new_sub_row,
            )
            pg_cursor.execute("COMMIT")
        except psycopg2.errors.UniqueViolation as e:
            logging.warning(
                "Skipping insert subscriber %s due to uniqueness error: %s ",
                new_sub_row,
                e,
            )
            pg_cursor.execute("ROLLBACK")

    mysql_cursor.close()
    mysql_conn.commit()


def migrate_static_ips(mysql_conn, pg_conn):
    mysql_cursor = mysql_conn.cursor()
    mysql_cursor.execute("BEGIN")
    pg_cursor = pg_conn.cursor()
    pg_cursor.execute("BEGIN TRANSACTION")

    mysql_cursor.execute("select imsi, ip from static_ips;")
    for row in mysql_cursor:
        imsi = row[0]
        ip = row[1]

        try:
            pg_cursor.execute("BEGIN TRANSACTION")
            pg_cursor.execute(
                """
                INSERT INTO static_ips("imsi", "ip")
                VALUES
                (%s, %s)""",
                [imsi, ip],
            )
            logging.debug(
                "Migrating static ip %s and imsi %s",
                ip,
                imsi,
            )
            pg_cursor.execute("COMMIT")
        except psycopg2.errors.UniqueViolation as e:
            logging.warning(
                "Skipping insert static ip %s for imsi %s due to uniqueness error: %s",
                ip,
                imsi,
                e,
            )
            pg_cursor.execute("ROLLBACK")

    mysql_cursor.close()
    mysql_conn.commit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Migrate from the legacy mysql/mariadb system to postgres."
    )
    parser.add_argument(
        "--mysql-db-name",
        help="The database name for the mysql data source, assumed the same as provided in the configuration file unless proveded.",
    )
    parser.add_argument(
        "--mysql-db-user",
        help="The database user for the mysql data source, assumed the same as provided in the configuration file unless proveded.",
    )
    parser.add_argument(
        "--mysql-db-pass",
        help="The database password for the mysql data source, assumed the same as provided in the configuration file unless proveded.",
    )
    parser.add_argument(
        "-c",
        "--config",
        default=Path("/etc/haulage/config.yml"),
        help="The location of a haulage config file (version 1)",
    )

    args = parser.parse_args()

    (config_db_name, config_db_user, config_db_pass) = read_haulage_config(args.config)

    pg_name = config_db_name
    pg_user = config_db_user
    pg_pass = config_db_pass

    mysql_name = args.mysql_db_name
    mysql_user = args.mysql_db_user
    mysql_pass = args.mysql_db_pass

    if mysql_name is None:
        mysql_name = config_db_name
    if mysql_user is None:
        mysql_user = config_db_user
    if mysql_pass is None:
        mysql_pass = config_db_pass

    mysql_connection = mysql.connector.connect(
        host="localhost", user=mysql_user, passwd=mysql_pass, db=mysql_name
    )
    logging.info("Connected to mysql/mariadb at db=%s, user=%s", mysql_name, mysql_user)

    pg_connection = psycopg2.connect(dbname=pg_name, user=pg_user, password=pg_pass)
    logging.info("Connected to postgres at db=%s, user=%s", pg_name, pg_user)

    logging.info("Beginning migration!")
    migrate_subscribers(mysql_connection, pg_connection)
    migrate_static_ips(mysql_connection, pg_connection)
