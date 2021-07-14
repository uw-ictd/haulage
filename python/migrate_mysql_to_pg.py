#!/usr/bin/env python3

import argparse
import logging

from pathlib import Path

import mysql.connector
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


def canonicalize_currency(code, symbol, name, pg_conn):
    # Check if the code is already registered
    code = code.upper()
    cursor = pg_conn.cursor()

    cursor.execute(
        """
        SELECT id, name, code, symbol
        FROM currencies
        WHERE code=%s;
        """,
        [code],
    )

    rows = cursor.fetchall()

    if len(rows) == 0:
        # Insert the new currency
        cursor.execute(
            """
            INSERT INTO currencies("name", "code", "symbol")
            VALUES
            (%s, %s, %s)
            """,
            [name, code, symbol],
        )

        cursor.execute(
            """
            SELECT id, name, code, symbol
            FROM currencies
            WHERE code=%s;
            """,
            [code],
        )
        inserted_id = cursor.fetchall()
        if len(inserted_id != 1):
            raise RuntimeError(
                "The just inserted currency code didn't match exactly one row, which should never happen."
            )

        return inserted_id[0][0]

    elif len(rows) == 1:
        # There was a single match, assert that the other parts match
        if (name is not None and rows[0][1] != name) or (
            symbol is not None and rows[0][3] != symbol
        ):
            logging.error(
                "Could not set the currency because the provided name and symbol do not match those of an existing currency already inserted at the same code"
            )
            logging.error("You attempted to insert %s, %s, %s", code, name, symbol)
            logging.error(
                "Which conflicts with the existing %s, %s, %s",
                rows[0][2],
                rows[0][1],
                rows[0][3],
            )
            raise RuntimeError("Cannot proceed with a currency conflict")

        return rows[0][0]
    else:
        raise RuntimeError(
            "The provided currency code matches multiple rows, which should never happen."
        )


def migrate_subscribers(mysql_conn, pg_conn, currency_id):
    mysql_conn.start_transaction(isolation_level="SERIALIZABLE")
    mysql_cursor = mysql_conn.cursor()
    pg_cursor = pg_conn.cursor()

    mysql_cursor.execute(
        "select imsi, username, raw_down, raw_up, data_balance, balance, bridged, enabled, admin, msisdn from customers;"
    )
    for row in mysql_cursor:
        if row[6] == 1:
            bridged = True
        else:
            bridged = False

        new_sub_row = [row[0], row[4], row[5], currency_id, bridged]

        try:
            pg_cursor.execute("BEGIN TRANSACTION")
            pg_cursor.execute(
                """
                INSERT INTO subscribers("imsi", "data_balance", "balance", "currency", "bridged")
                VALUES
                (%s, %s, %s, %s, %s)""",
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
    mysql_conn.start_transaction(isolation_level="SERIALIZABLE")
    mysql_cursor = mysql_conn.cursor()
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
        "--currency",
        required=True,
        help="The three character ISO 4217 currency code of the balance currency used by the legacy database",
    )
    parser.add_argument(
        "--currency-symbol",
        help="The currency symbol for the currency used by the legacy database",
    )
    parser.add_argument(
        "--currency-name",
        help="The plain name of the currency used by the legacy database",
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
    legacy_currency_id = canonicalize_currency(
        args.currency, args.currency_symbol, args.currency_name, pg_connection
    )
    migrate_subscribers(mysql_connection, pg_connection, legacy_currency_id)
    migrate_static_ips(mysql_connection, pg_connection)
