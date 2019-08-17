# File for accessing MySQL data

import MySQLdb

def mysql_connect(hostname, username, password, dbname):
    try:
        connection = MySQLdb.connect(hostname, username, password, dbname)

    except:
        print("Error: can't connect to db")
        return 0

    print("Connected to db")

    cursor = connection.cursor()
    cursor.execute("SELECT * FROM servicelogs")
    for row in cursor.fetchall():
        print row
    #cursor.execute("INSERT INTO servicelogs(service, totalbytes, numusers) VALUES ('Whatsapp', 1, 1)")
    cursor.execute("SELECT * FROM servicelogs")
    for row in cursor.fetchall():
        print row

    cursor.close()
    connection.commit()
    connection.close()

mysql_connect("localhost", "colte_db", "colte_db", "colte_db")
