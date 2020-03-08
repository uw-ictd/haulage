import MySQLdb
import os
import sys
import decimal
import yaml

#########################################################################
############### SETUP: LOAD YAML VARS AND CONNECT TO DB #################
#########################################################################

file = open('../config.yml')
conf = yaml.load(file, Loader=yaml.FullLoader)
dbname = conf['custom']['dbLocation']
db_user = conf['custom']['dbUser']
db_pass = conf['custom']['dbPass']

db = MySQLdb.connect(host="localhost",
                     user=db_user,
                     passwd=db_pass,
		     	 	 db=dbname)
cursor = db.cursor()

num_args = len(sys.argv)
command = sys.argv[4]

#########################################################################
############### OPTION ONE: ADD A USER TO THE DATABASE ##################
#########################################################################
if (command == "add"):
	imsi = sys.argv[5]
	msisdn = sys.argv[6]
	ip = sys.argv[7]
	key = sys.argv[8]
	opc = sys.argv[9]

	# TODO: error-handling? Check if imsi/msisdn/ip already in system?
	print("haulagedb: adding user " + str(imsi))

	commit_str = "INSERT INTO customers (imsi, msisdn) VALUES ('" + imsi + "', '" + msisdn + "')"
	cursor.execute(commit_str)

	# ip = GENERATE IP ADDRESS?!?
	commit_str = "INSERT INTO static_ips (imsi, ip) VALUES ('" + imsi + "', '" + ip + "')"
	cursor.execute(commit_str)

#########################################################################
############### OPTION TWO: REMOVE USER FROM THE DATABASE ###############
#########################################################################
elif (command == "remove"):
	imsi = sys.argv[5]

	print("haulagedb: removing user " + str(imsi))

	commit_str = "DELETE FROM customers WHERE imsi = " + imsi
	cursor.execute(commit_str)

	commit_str = "DELETE FROM static_ips WHERE imsi = " + imsi
	cursor.execute(commit_str)

#########################################################################
############### OPTION THREE: TOPUP (ADD BALANCE TO USER) ###############
#########################################################################
elif (command == "topup"):
	imsi = sys.argv[5]
	amount = decimal.Decimal(sys.argv[6])
	old_balance = 0
	new_balance = 0

	#STEP ONE: query information
	# SMS TODO #1: check for decimal overflow?!?
	# SMS TODO #2: improve this for-loop code?!?
	commit_str = "SELECT balance FROM customers WHERE imsi = " + imsi + " FOR UPDATE"
	numrows = cursor.execute(commit_str)
	if (numrows == 0):
		print("haulagedb error: imsi " + str(imsi) + " does not exist!")
		exit()

	for row in cursor:
		old_balance = decimal.Decimal(row[0])
		new_balance = amount + old_balance

	# STEP TWO: prompt for confirmation
	promptstr = "haulagedb: topup user " + str(imsi) + " add " + str(amount) + " to current balance " + str(old_balance) + " to create new balance " + str(new_balance) + "? [Y/n] "
	while True:
		answer = raw_input(promptstr)
		if (answer == 'y' or answer == 'Y' or answer == ''):
			print("haulagedb: updating user " + str(imsi) + " setting new balance to " + str(new_balance))
			commit_str = "UPDATE customers SET balance = " + str(new_balance) + " WHERE imsi = " + imsi
			cursor.execute(commit_str)
			break
		if (answer == 'n' or answer == 'N'):
			print("haulagedb: cancelling topup operation\n")
			break

#########################################################################
############### OPTION FOUR: DISABLE A USER (AND ZERO-OUT BALANCE???) ###
#########################################################################
elif (command == "disable"):
	imsi = sys.argv[5]

	print("haulagedb: disabling user " + str(imsi))

	commit_str = "UPDATE customers SET enabled = 0, data_balance = 0 WHERE imsi = " + imsi
	cursor.execute(commit_str)

elif (command == "enable"):
	imsi = sys.argv[5]

	print("haulagedb: enabling user " + str(imsi))

	commit_str = "UPDATE customers SET enabled = 1, data_balance = 10000000 WHERE imsi = " + imsi
	cursor.execute(commit_str)

elif (command == "admin"):
	imsi = sys.argv[5]

	print("haulagedb: giving admin privileges to user " + str(imsi))

	commit_str = "UPDATE customers SET admin = 1 WHERE imsi = " + imsi
	cursor.execute(commit_str)

elif (command == "noadmin"):
	imsi = sys.argv[5]

	print("haulagedb: removing admin privileges from user " + str(imsi))

	commit_str = "UPDATE customers SET admin = 0 WHERE imsi = " + imsi
	cursor.execute(commit_str)

db.commit()
cursor.close()
db.close()