#!/bin/bash

echo "This script changes the password of the root user of MySQL to empty. Run it to allow the system to work as a development machine for F-PKI."

str="ALTER USER root@localhost IDENTIFIED WITH mysql_native_password BY '';
FLUSH PRIVILEGES;
"
echo "$str" | sudo mysql
