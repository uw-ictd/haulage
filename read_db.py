# File for accessing MySQL data

import MySQLdb
import csv
import time


HOSTNAME = "localhost"
USERNAME = "colte_db"
PASSWORD = "colte_db"
DBNAME = "colte_db"

SERVICES = ['whatsapp', 'facebook', 'youtube']

TP_OUTFILE = 'tp_data.tsv'
USERS_OUTFILE = 'users_data.tsv'


def servicelogs_init(services):
    try:
        connection = MySQLdb.connect(HOSTNAME, USERNAME, PASSWORD, DBNAME)
    except:
        print("Error: can't connect to db to init services")
        return 0

    cursor = connection.cursor()
    for s in services:
        try:
            cursor.execute("INSERT INTO servicelogs(service, totalbytes, numusers) VALUES (%s, 0, 0)", (s,))
        except:
            print("Error: db INSERT failed on %s".format(s))

    # DEBUG
    cursor.execute("SELECT * FROM servicelogs")
    for row in cursor.fetchall():
        print row

    # close connection
    cursor.close()
    connection.commit()
    connection.close()


def servicelogs_get(services):
    new_nums = []

    try:
        connection = MySQLdb.connect(HOSTNAME, USERNAME, PASSWORD, DBNAME)
    except:
        print("Error: can't connect to db to update")
        return 0

    cursor = connection.cursor()
    for s in services:
        cursor.execute("SELECT * from servicelogs WHERE service = %s", (s,))
        # there should only be one row otherwise something is wrong
        tup = cursor.fetchone()
        print tup
        new_nums.append(tup)

    # DEBUG
    #cursor.execute("SELECT * FROM servicelogs")
    #for row in cursor.fetchall():
    #    print row

    # close connection
    cursor.close()
    connection.commit()
    connection.close()

    return new_nums


def process_data(data):
    throughputs = []
    users = []
    for service in data:
        throughputs.append(service[1])
        users.append(service[2])
    return throughputs, users 


def write_to_tsv(fn, data):
    with open(fn, 'a') as f:
        writer = csv.writer(f, delimiter='\t')
        writer.writerow(data)


# main
# TODO need to figure out how to initialize all this 

def main():
    # init functions
    #servicelogs_init(SERVICES)
    #write_to_tsv(TP_OUTFILE, SERVICES)
    #write_to_tsv(USERS_OUTFILE, SERVICES)

    new_data = servicelogs_get(SERVICES)
    tps, users = process_data(new_data)

    write_to_tsv(TP_OUTFILE, tps)
    write_to_tsv(USERS_OUTFILE, users)
    

if __name__ == "__main__":
    main()
