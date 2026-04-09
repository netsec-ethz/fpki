# Development tools


## Installing the database

Based on [https://linuxhint.com/installing_mysql_workbench_ubuntu/](https://linuxhint.com/installing_mysql_workbench_ubuntu/).
- Download [mysql-apt-config](https://dev.mysql.com/downloads/repo/apt/) and install it with e.g. `sudo apt install mysql-apt-config_0.8.22-1_all.deb`.
- Select the version if the preselected one is not good.
- Install "mysql-community-server" `sudo apt install mysql-community-server`
- Allow local config for apparmor mysqld:
```bash
sudo sed -i 's/#include <local\/usr.sbin.mysqld>/include <local\/usr.sbin.mysqld>/' /etc/apparmor.d/usr.sbin.mysqld
sudo systemctl restart apparmor.service
```
- Ensure that the apparmor configuration allows access to the data mount point (necessary for LOAD DATA INFILE).
  E.g., add `/mnt/data/mysql` to `/etc/apparmor.d/local/usr.sbin.mysqld`:
```bash
echo "# Site-specific additions and overrides for usr.sbin.mysqld.
# For more details, please see /etc/apparmor.d/local/README.

# Allow access to files:
  /mnt/data/ r,
  /mnt/data/** rw,
  /tmp/ r,
  /tmp/** rw,
  /mnt/data/tmp/ r,
  /mnt/data/tmp/**  rw,
" | sudo tee -a /etc/apparmor.d/local/usr.sbin.mysqld
sudo systemctl restart apparmor.service
```

If the data directory under `/var/lib/mysql/` needs to be initialized, run `mysqld --initialize-insecure`.

To allow root without password:
```bash
echo "ALTER USER 'root'@'localhost' IDENTIFIED WITH caching_sha2_password BY '';
FLUSH PRIVILEGES;" | sudo mysql
# you should see "caching_sha2_password" as plugin for root when displaying the root user:
mysql -u root -e "SELECT user,authentication_string,plugin,host FROM mysql.user;"
```
Previously we suggested to use the option `mysql_native_password` instead of `caching_sha2_password`,
but since MySQL version 9 it has been deprecated and removed.

## Running MySQL 9.4 via Docker Compose

If you want to try the MySQL 9.4 server binary while reusing the host configuration,
there is a compose file at [`docker-compose.mysql94.yml`](/home/juagargi/devel/ETH/fpki/tools/docker-compose.mysql94.yml).

It keeps the image's own `/etc/my.cnf` and mounts:

- `tools/db_setup/fpki.cnf` into `/etc/mysql/conf.d/fpki.cnf`
- a Docker-managed volume at `/var/lib/mysql`
- `/var/run/mysqld` so the host socket path remains available
- `/mnt/data/tmp` because `fpki.cnf` points `tmpdir` and `secure_file_priv` there

Typical workflow:

```bash
sudo systemctl stop mysql # or mysqld
sudo docker compose -f tools/docker-compose.mysql94.yml up
```

In another shell, check:

```bash
mysql -u root -e "SELECT VERSION();"
mysql -u root -e "SHOW VARIABLES LIKE 'open_files_limit';"
```

When done:

```bash
sudo docker compose -f tools/docker-compose.mysql94.yml down
sudo rc-service mysql start
```

Important caveats:

- Stop the host mysql service first, or the port and socket will conflict.
- This compose file keeps the image defaults from `/etc/my.cnf` and layers only `fpki.cnf` on top.
- This no longer reuses the host `/var/lib/mysql`, so it avoids the MySQL 8.x -> 9.x upgrade restriction you hit.
- The first startup initializes a fresh MySQL 9.4 datadir inside the named Docker volume `mysql94-data`.
- To wipe the container datadir and start over, remove the compose volume:

```bash
sudo docker compose -f tools/docker-compose.mysql94.yml down -v
```


## System

Don't forget to change the kernel parameters to allow a higher number of AIO operations.
In `/etc/sysctl.conf` add the line `fs.aio-max-nr = 1048576`.

And look at the `fpki.cnf` file in this repository to copy those values inside `/etc/mysql/conf.d/`.

## Analyze performance

DESCRIBE SELECT * FROM nodes WHERE id=1234;



## Reference

[Expected performance of a DB cluster](https://www.mysql.com/why-mysql/benchmarks/mysql-cluster/)
[MySQL noSQL](https://www.mysql.com/why-mysql/white-papers/guide-to-mysql-and-nosql-delivering-the-best-of-both-worlds/)



```
use fpki;

drop procedure if exists doWhile;
DELIMITER //
CREATE PROCEDURE doWhile()
BEGIN
DECLARE i INT DEFAULT 1;
WHILE (i <= 32) DO
    INSERT INTO `fpki`.`nodes` (`id`) VALUES (i);
    SET i = i+1;
END WHILE;
END;
//

CALL doWhile();
```

To rename a DB in MySQL, RENAME doesn't work. We have to create a new empty DB and move each one of the tables there.


```bash
mysql -u root -s -e 'DROP DATABASE IF EXISTS fpki_bak; CREATE DATABASE fpki_bak /*!40100 DEFAULT CHARACTER SET binary */ /*!80016 DEFAULT ENCRYPTION='N' */;'

# -s (silent)
# -N skip column names
# -e "execute SQL"
for table in `mysql -u root -s -N -e "use fpki;show tables from fpki;"`; do
  mysql -u root -s -N -e "use fpki;rename table fpki.$table to fpki_bak.$table;";
done;
```
