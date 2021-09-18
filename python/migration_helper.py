#!/usr/bin/env python3

import argparse
import collections
import ipaddress
import logging

from pathlib import Path

import MySQLdb
import pymongo
import psycopg2
import yaml

logging.basicConfig(level=logging.DEBUG)

IpMapping = collections.namedtuple("IpMapping", ["imsi", "ip"])


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


def _prune_imsi(imsi_stem, input_imsi):
    stem = input_imsi[0 : len(imsi_stem)]
    leaf = input_imsi[len(imsi_stem) :]

    if stem != imsi_stem:
        raise ValueError(
            "The input imsi {} does not match the stem {}".format(input_imsi, imsi_stem)
        )

    return leaf


def ip_mapper(imsi_stem, base_network, old_mapping):
    old_imsi = old_mapping.imsi
    imsi_serial = _prune_imsi(imsi_stem, old_imsi)
    imsi_serial = int(imsi_serial)

    new_ip = ipaddress.IPv4Address(int(base_network) + imsi_serial)

    if new_ip not in base_network.network:
        raise ValueError(
            "Mapped ip {} exceeded the availabe range of the new network {}".format(
                new_ip,
                base_network.network,
            )
        )

    return IpMapping(imsi=old_imsi, ip=new_ip)


def remap_static_ips(pg_conn):
    pg_cursor = pg_conn.cursor()
    pg_cursor.execute("BEGIN TRANSACTION")

    new_base = ipaddress.ip_address("10.45.1.0/16")

    try:
        pg_cursor.execute("select imsi, ip from static_ips;")
        for row in pg_cursor:
            imsi = row[0]
            ip = row[1]

            existing_mapping = IpMapping(imsi=imsi, ip=ipaddress.IPv4Address(ip))

            new_mapping = ip_mapper(
                "91054000",
                new_base,
                existing_mapping,
            )

            pg_cursor.execute(
                """
                UPDATE static_ips
                SET "ip"=%s
                WHERE "imsi"=%s
                """,
                [new_mapping.ip, new_mapping.imsi],
            )
            logging.debug(
                "Remapping static ip %s to %s for imsi %s",
                ip,
                new_mapping.ip,
                new_mapping.imsi,
            )
        pg_cursor.execute("COMMIT")
    except psycopg2.IntegrityError as e:
        logging.warning(
            "Skipping insert static ip %s for imsi %s due to error: %s",
            ip,
            imsi,
            e,
        )
        pg_cursor.execute("ROLLBACK")


def remap_open5gs_ips(mongo_collection):
    """Remap all ip addresses in the open5gs db"""

    new_base = ipaddress.ip_address("10.45.1.0/16")

    for x in mongo_collection.find():
        imsi = x["imsi"]
        print("Subscriber record " + str(imsi) + " is loaded")

        existing_mapping = IpMapping(
            imsi=imsi,
            ip=ipaddress.IPv4Address(x["slice"][0]["session"][0]["ue"]["addr"]),
        )

        new_mapping = ip_mapper(
            "91054000",
            new_base,
            existing_mapping,
        )

        updated_ip = {"slice": [{"session": [{"ue": {"addr": str(new_mapping.ip)}}]}]}

        # Write back to MongoDB
        myquery = {"imsi": str(imsi)}
        newvalues = {"$set": updated_ip}
        mongo_collection.update_one(myquery, newvalues)
        print("Updated OK")


def sync_balances(mysql_conn, pg_conn):
    mysql_cursor = mysql_conn.cursor()
    mysql_cursor.execute("BEGIN")
    pg_cursor = pg_conn.cursor()

    mysql_cursor.execute(
        "select imsi, data_balance, balance, bridged, enabled from customers;"
    )
    for row in mysql_cursor:
        if row[3] == 1:
            bridged = True
        else:
            bridged = False

        if row[4] == 1:
            enabled = True
        else:
            enabled = False

        try:
            pg_cursor.execute("BEGIN TRANSACTION")
            pg_cursor.execute(
                """
                UPDATE subscribers
                SET ("data_balance", "bridged") = (%s, %s)
                WHERE "imsi"=%s""",
                [row[1], bridged, row[0]],
            )
            logging.debug(
                "Updating subscriber data balance -> subscriber source row %s -> new balance and bridged %s",
                row,
                [row[1], bridged],
            )
            pg_cursor.execute(
                """
                UPDATE customers
                SET ("balance", "enabled") = (%s, %s)
                WHERE "imsi"=%s""",
                [row[2], enabled, row[0]],
            )
            logging.debug(
                "Updating subscriber balance -> subscriber source row %s -> new balance and enabled %s",
                row,
                [row[2], enabled],
            )

            pg_cursor.execute("COMMIT")
        except psycopg2.IntegrityError as e:
            logging.warning(
                "Skipping update from original %s due to error: %s ",
                row,
                e,
            )
            pg_cursor.execute("ROLLBACK")

    mysql_cursor.close()
    mysql_conn.commit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Programatically generate new static ip assignments."
    )
    parser.add_argument(
        "-c",
        "--config",
        default=Path("/etc/haulage/config.yml"),
        help="The location of a haulage config file (version 1)",
    )

    parser.add_argument(
        "--remap-ips",
        help="Whether to remap ip addresses",
    )

    parser.add_argument(
        "--sync-balances",
        help="Whether to remap ip addresses",
    )

    args = parser.parse_args()

    (config_db_name, config_db_user, config_db_pass) = read_haulage_config(args.config)

    pg_name = config_db_name
    pg_user = config_db_user
    pg_pass = config_db_pass

    pg_connection = psycopg2.connect(
        dbname=pg_name, user=pg_user, password=pg_pass, host="127.0.0.1"
    )
    logging.info("Connected to postgres at db=%s, user=%s", pg_name, pg_user)

    mongo_connection = pymongo.MongoClient("mongodb://localhost:27017/")
    mongo_database = mongo_connection["open5gs"]
    logging.info("Connected to mongo at %s", mongo_connection)

    if args.remap_ips:
        logging.info("Beginning postgres remapping!")
        remap_static_ips(pg_connection)
        logging.info("Beginning open5gs mongo remapping!")
        remap_open5gs_ips(mongo_collection=mongo_database["subscribers"])

    if args.sync_balances:
        mysql_name = config_db_name
        mysql_user = config_db_user
        mysql_pass = config_db_pass

        mysql_connection = MySQLdb.connect(
            host="localhost", user=mysql_user, passwd=mysql_pass, db=mysql_name
        )
        logging.info(
            "Connected to mysql/mariadb at db=%s, user=%s", mysql_name, mysql_user
        )
        sync_balances(mysql_connection, pg_connection)
