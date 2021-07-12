### if running, stop it
sudo systemctl stop haulage
sudo systemctl disable haulage
sudo systemctl daemon-reload

### ONLY if purging, remove database and user
if [ "$1" = purge ]; then
	# remove haulage_db user and database
	sudo mysql -e "DROP DATABASE IF EXISTS haulage_db;"
	sudo mysql -e "DROP USER IF EXISTS haulage_db@localhost;"
	sudo mysql -e "FLUSH PRIVILEGES;"
	echo "Purged haulage_db user and database"
fi

echo "Uninstalled haulage"
