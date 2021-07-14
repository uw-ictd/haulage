#!/usr/bin/env python3

import MySQLdb
import os
import sys
import decimal
import yaml

def display_help():
	print("COMMANDS:")
	print("   add {imsi msisdn ip}: adds a user to the network")
	print("   remove {imsi}: removes a user from the network")
	print("   topup {imsi} {bytes}: adds bytes to a user's account")
	print("   help: displays this message and exits")


#########################################################################
############### SETUP: LOAD YAML VARS AND CONNECT TO DB #################
#########################################################################
print("haulagedb: Haulage Database Configuration Tool")

if (len(sys.argv) <= 1):
	display_help()
	exit(0)

command = sys.argv[1]

if (command == "help"):
	display_help()
	exit(0)

if os.geteuid() != 0:
	print("haulagedb: Must run as root!")
	exit(1)

file = open('/etc/haulage/config.yml')
conf = yaml.load(file, Loader=yaml.BaseLoader)
dbname = conf['custom']['dbLocation']
db_user = conf['custom']['dbUser']
db_pass = conf['custom']['dbPass']

db = MySQLdb.connect(host="localhost",
                     user=db_user,
                     passwd=db_pass,
		     	 	 db=dbname)
cursor = db.cursor()

#########################################################################
############### OPTION ONE: ADD A USER TO THE DATABASE ##################
#########################################################################
if (command == "add"):
	if len(sys.argv) != 5:
		print("haulagedb: incorrect number of args, format is \"haulagedb add imsi msisdn ip\"")
		exit(1)

	imsi = sys.argv[2]
	msisdn = sys.argv[3]
	ip = sys.argv[4]

	# TODO: error-handling? Check if imsi/msisdn/ip already in system?
	print("haulagedb: adding user " + str(imsi))

	commit_str = "INSERT INTO customers (imsi, msisdn) VALUES ('" + imsi + "', '" + msisdn + "')"
	cursor.execute(commit_str)

	commit_str = "INSERT INTO static_ips (imsi, ip) VALUES ('" + imsi + "', '" + ip + "')"
	cursor.execute(commit_str)

#########################################################################
############### OPTION TWO: REMOVE USER FROM THE DATABASE ###############
#########################################################################
elif (command == "remove"):
	if len(sys.argv) != 3:
		print("haulagedb: incorrect number of args, format is \"haulagedb remove imsi\"")
		exit(1)

	imsi = sys.argv[2]

	print("haulagedb: removing user " + str(imsi))

	commit_str = "DELETE FROM customers WHERE imsi = " + imsi
	cursor.execute(commit_str)

	commit_str = "DELETE FROM static_ips WHERE imsi = " + imsi
	cursor.execute(commit_str)

#########################################################################
############### OPTION THREE: TOPUP (ADD BALANCE TO USER) ###############
#########################################################################
elif (command == "topup"):
	if len(sys.argv) != 4:
		print("haulagedb: incorrect number of args, format is \"haulagedb topup imsi bytes\"")
		exit(1)

	imsi = sys.argv[2]
	amount = decimal.Decimal(sys.argv[3])
	old_balance = 0
	new_balance = 0

	#STEP ONE: query information
	commit_str = "SELECT data_balance FROM customers WHERE imsi = " + imsi + " FOR UPDATE"
	numrows = cursor.execute(commit_str)
	if (numrows == 0):
		print("haulagedb error: imsi " + str(imsi) + " does not exist!")
		exit()

	for row in cursor:
		old_balance = decimal.Decimal(row[0])
		new_balance = amount + old_balance

	# STEP TWO: prompt for confirmation
	promptstr = "haulagedb: topup user " + str(imsi) + " add " + str(amount) + " bytes to current balance of " + str(old_balance) + " bytes to create new data_balance of " + str(new_balance) + "? [Y/n] "
	while True:
		answer = input(promptstr)
		if (answer == 'y' or answer == 'Y' or answer == ''):
			print("haulagedb: updating user " + str(imsi) + " setting new data_balance to " + str(new_balance))
			commit_str = "UPDATE customers SET data_balance = " + str(new_balance) + " WHERE imsi = " + imsi
			cursor.execute(commit_str)
			break
		if (answer == 'n' or answer == 'N'):
			print("haulagedb: cancelling topup operation\n")
			break

else:
	display_help()
	exit(0)

db.commit()
cursor.close()
db.close()

