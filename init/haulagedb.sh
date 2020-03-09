#!/bin/bash

script=/usr/bin/haulagedb.py
version=0.9.5

display_help() {
    echo "COMMANDS:" >&2
    echo "   add {imsi msisdn ip}: adds a user to the network"
    echo "   remove {imsi}: removes a user from the network"
    echo "   topup {imsi} {money}: adds money to a user's account"
    # echo "   disable {imsi}: sets a user's balance to 0 and kicks them off the network"
    # echo "   enable {imsi}: gives a user 10MB of data and adds them to the network"
    # echo "   admin {imsi}: gives a user administrative privileges"
    # echo "   noadmin {imsi}: removes a user's administrative privileges"
    # echo "   sync: runs a sync script to ensure that the database configuration is sane"
    # echo "   reset: WIPES OUT the database and restores it to the sample default"
    echo "   help: displays this message and exits"
    # ANY OTHER VALUES?!?!?!
}

echo "haulagedb: Haulage Database Configuration Tool ($version)"

if [ "$#" -lt 1 ]; then
	display_help
	exit 1
fi

if [ "$1" = "help" ]; then
	display_help
	exit 1
fi

if [ "$EUID" -ne 0 ]; then
	echo "haulagedb: Must run as root!"
	exit 1
fi

if [ "$1" = "add" ]; then
	if [ "$#" -ne 4 ]; then
		echo "haulagedb: incorrect number of args, format is \"haulagedb add imsi msisdn ip\""
		exit 1
	fi
	python3 $script $1 $2 $3 $4
	exit 0
fi

if [ "$1" = "remove" ]; then
	if [ "$#" -ne 2 ]; then
		echo "haulagedb: incorrect number of args, format is \"haulagedb remove imsi\""
		exit 1
	fi
	python3 $script $1 $2
	exit 0
fi

if [ "$1" = "topup" ]; then
	if [ "$#" -ne 3 ]; then
		echo "haulagedb: incorrect number of args, format is \"haulagedb topup imsi money\""
		exit 1
	fi
	python3 $script $1 $2 $3
	exit 0
fi

# if [ "$1" = "disable" ]; then
# 	if [ "$#" -ne 2 ]; then
# 		echo "haulagedb: incorrect number of args, format is \"haulagedb disable imsi\""
# 		exit 1
# 	fi
# 	python3 $script $1 $2
# 	exit 0
# fi

# if [ "$1" = "enable" ]; then
# 	if [ "$#" -ne 2 ]; then
# 		echo "haulagedb: incorrect number of args, format is \"haulagedb enable imsi\""
# 		exit 1
# 	fi
# 	python3 $script $1 $2
# 	exit 0
# fi

# if [ "$1" = "admin" ]; then
# 	if [ "$#" -ne 2 ]; then
# 		echo "haulagedb: incorrect number of args, format is \"haulagedb admin imsi\""
# 		exit 1
# 	fi
# 	python3 $script $1 $2
# 	exit 0
# fi

# if [ "$1" = "noadmin" ]; then
# 	if [ "$#" -ne 2 ]; then
# 		echo "haulagedb: incorrect number of args, format is \"haulagedb noadmin imsi\""
# 		exit 1
# 	fi
# 	python3 $script $1 $2
# 	exit 0
# fi

# if [ "$1" = "reset" ]; then
# 	mysql -u $user -p$pass $db < /usr/local/etc/colte/sample_db.sql
# 	echo "haulagedb: reset database."
# 	exit 0
# fi

# if [ "$1" = "sync" ]; then
# 	if [ "$#" -ne 1 ]; then
# 		echo "haulagedb: incorrect number of args, format is \"haulagedb sync\""
# 		exit 1
# 	fi
# 	python3 $script sync
# fi

display_help
