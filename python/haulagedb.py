#!/usr/bin/env python3

import sys
import decimal
import yaml

import psycopg2


def display_help():
    print("COMMANDS:")
    print("   add {imsi msisdn ip [currency_code]}: adds a user to the network")
    print("   remove {imsi}: removes a user from the network")
    print("   topup {imsi} {bytes}: adds bytes to a user's account")
    print("   help: displays this message and exits")


#########################################################################
############### SETUP: LOAD YAML VARS AND CONNECT TO DB #################
#########################################################################
print("haulagedb: Haulage Database Configuration Tool")

if len(sys.argv) <= 1:
    display_help()
    exit(0)

command = sys.argv[1]

if command == "help":
    display_help()
    exit(0)

with open("/etc/haulage/config.yml") as f:
    conf = yaml.load(f, Loader=yaml.SafeLoader)
    dbname = conf["custom"]["dbLocation"]
    db_user = conf["custom"]["dbUser"]
    db_pass = conf["custom"]["dbPass"]

db = psycopg2.connect(host="localhost", user=db_user, password=db_pass, dbname=dbname)
cursor = db.cursor()

#########################################################################
############### OPTION ONE: ADD A USER TO THE DATABASE ##################
#########################################################################
if command == "add":
    if (len(sys.argv) < 5) or (len(sys.argv) > 6):
        print(
            'haulagedb: incorrect number of args, format is "haulagedb add imsi msisdn ip [currency_code]"'
        )
        exit(1)

    imsi = sys.argv[2]
    msisdn = sys.argv[3]
    ip = sys.argv[4]

    if len(sys.argv) > 5:
        currency = sys.argv[5]
    else:
        currency = "IDR"

    # TODO: error-handling? Check if imsi/msisdn/ip already in system?
    print("haulagedb: adding user " + str(imsi))

    cursor.execute("BEGIN TRANSACTION")

    cursor.execute(
        """
        SELECT id FROM currencies WHERE code=%s
        """,
        [currency],
    )
    currency_ids = cursor.fetchall()
    if len(currency_ids) != 1:
        raise RuntimeError(
            "Invalid currency code {}, try one like IDR or USD".format(currency)
        )

    cursor.execute(
        """
        INSERT INTO subscribers (imsi, currency)
        VALUES
        (%s, %s)
        """,
        [imsi, currency_ids[0][0]],
    )

    commit_str = (
        "INSERT INTO static_ips (imsi, ip) VALUES ('" + imsi + "', '" + ip + "')"
    )
    cursor.execute(commit_str)

    cursor.execute("COMMIT")

#########################################################################
############### OPTION TWO: REMOVE USER FROM THE DATABASE ###############
#########################################################################
elif command == "remove":
    if len(sys.argv) != 3:
        print('haulagedb: incorrect number of args, format is "haulagedb remove imsi"')
        exit(1)

    imsi = sys.argv[2]

    print("haulagedb: removing user " + str(imsi))

    cursor.execute("BEGIN TRANSACTION")

    cursor.execute(
        """
        DELETE FROM static_ips
        WHERE imsi=%s
        """,
        [imsi],
    )

    cursor.execute(
        """
        DELETE FROM subscriber_history
        WHERE subscriber IN (
            SELECT internal_uid
            FROM subscribers
            WHERE imsi=%s
        )
        """,
        [imsi],
    )

    cursor.execute(
        """
        DELETE FROM subscribers WHERE imsi=%s
        """,
        [imsi],
    )

    cursor.execute("COMMIT")

#########################################################################
############### OPTION THREE: TOPUP (ADD BALANCE TO USER) ###############
#########################################################################
elif command == "topup":
    if len(sys.argv) != 4:
        print(
            'haulagedb: incorrect number of args, format is "haulagedb topup imsi bytes"'
        )
        exit(1)

    imsi = sys.argv[2]
    amount = decimal.Decimal(sys.argv[3])
    old_balance = 0
    new_balance = 0

    cursor.execute("BEGIN TRANSACTION")

    # STEP ONE: query information
    numrows = cursor.execute(
        """
        SELECT data_balance, internal_uid
        FROM subscribers
        WHERE imsi=%s
        FOR UPDATE
        """,
        [imsi],
    )
    if numrows == 0:
        print("haulagedb error: imsi " + str(imsi) + " does not exist!")
        exit()

    for row in cursor:
        old_balance = decimal.Decimal(row[0])
        new_balance = amount + old_balance

    # STEP TWO: prompt for confirmation
    promptstr = (
        "haulagedb: topup user "
        + str(imsi)
        + " add "
        + str(amount)
        + " bytes to current balance of "
        + str(old_balance)
        + " bytes to create new data_balance of "
        + str(new_balance)
        + "? [Y/n] "
    )
    while True:
        answer = input(promptstr)
        if answer == "y" or answer == "Y" or answer == "":
            print(
                "haulagedb: updating user "
                + str(imsi)
                + " setting new data_balance to "
                + str(new_balance)
            )
            cursor.execute(
                """
                UPDATE subscribers
                SET data_balance = %s
                WHERE imsi = %s
                RETURNING internal_uid, data_balance, balance, bridged
                """,
                [new_balance, imsi],
            )
            new_sub_state = cursor.fetchall()
            if len(new_sub_state) != 1:
                raise RuntimeError("Database state invalid, too many records updated")
            new_sub_state = new_sub_state[0]
            cursor.execute(
                """
                INSERT INTO subscriber_history(subscriber, time, data_balance, balance, bridged)
                VALUES
                (%s, CURRENT_TIMESTAMP, %s, %s, %s)
                """,
                [
                    new_sub_state[0],
                    new_sub_state[1],
                    new_sub_state[2],
                    new_sub_state[3],
                ],
            )
            cursor.execute("COMMIT")
            break
        if answer == "n" or answer == "N":
            cursor.execute("ROLLBACK")
            print("haulagedb: cancelling topup operation\n")
            break

else:
    display_help()
    exit(0)

db.commit()
cursor.close()
db.close()
