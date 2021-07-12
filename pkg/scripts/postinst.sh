#!/usr/bin/env bash

### ONLY create the database if it doesn't already exist!
if [[ $(sudo -u postgres psql -c "\l haulage_db;" -At) ]]; then
	echo "warning: haulage_db already exists. Not updating the DB, just to be safe..."
else
	# create haulage_db user and database
	sudo -u postgres psql -c "CREATE DATABASE haulage_db;"
	sudo -u postgres psql -c "CREATE ROLE haulage_db WITH LOGIN ENCRYPTED PASSWORD 'haulage_db';"
	sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE haulage_db TO haulage_db;"
	echo "created haulage database and local user"
	haulage --db-upgrade
fi

systemctl daemon-reload
systemctl restart haulage.service

echo "Installed haulage"
