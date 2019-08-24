# File for accessing MySQL data

import MySQLdb
import csv
import os.path


HOSTNAME = "localhost"
USERNAME = "colte_db"
PASSWORD = "colte_db"
DBNAME = "colte_db"

TP_OUTFILE = 'throughput_data.tsv'


def servicelogs_get(fn):
    try:
        connection = MySQLdb.connect(HOSTNAME, USERNAME, PASSWORD, DBNAME)
    except:
        print("Error: can't connect to db to update")
        return 0

    cursor = connection.cursor()
    cursor.execute("SELECT * from servicelogs")
    data = cursor.fetchall()
    tp_data = process_tp_data(data)
    if os.path.exists(fn):
        write_to_tsv(fn, tp_data)
    else:
        names = process_names(data) 
        with open(fn, 'w+') as f:
            writer = csv.writer(f, delimiter='\t')
            writer.writerow(names)
            writer.writerow(tp_data)
    # close connection
    cursor.close()
    connection.commit()
    connection.close()
    return tp_data

def process_names(data):
    names = []
    for service in data:
        names.append(service[0])
    return names

def process_tp_data(data):
    throughputs = []
    for service in data:
        throughputs.append(service[2])
    return throughputs

def write_to_tsv(fn, datarow):
    with open(fn, 'a') as f:
        writer = csv.writer(f, delimiter='\t')
        writer.writerow(datarow)


# main

def main():
    new_data = servicelogs_get(TP_OUTFILE) 

if __name__ == "__main__":
    main()
