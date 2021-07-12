#!/usr/bin/env bash

### ONLY if purging, remove database and user
if [ "$1" = purge ]; then
	# remove haulage_db user and database
	sudo -u postgres psql -c "DROP DATABASE IF EXISTS haulage_db;"
	sudo -u postgres psql -c "DROP ROLE IF EXISTS haulage_db;"
	echo "Purged haulage_db user and database"
fi

echo "Uninstalled haulage"
