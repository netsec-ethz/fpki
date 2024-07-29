# Develpment tools


## Installing the database

Based on [https://linuxhint.com/installing_mysql_workbench_ubuntu/](https://linuxhint.com/installing_mysql_workbench_ubuntu/).
- Download [mysql-apt-config](https://dev.mysql.com/downloads/repo/apt/) and install it with e.g. `sudo apt install mysql-apt-config_0.8.22-1_all.deb`.
- Select the version if the preselected one is not good.
- Install "mysql-server" `sudo apt install mysql-community-server`
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

To allow root without password:
```bash
echo "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '';
FLUSH PRIVILEGES;" | sudo mysql
# you should see "mysql_native_password" as plugin for root when displaying the root user:
mysql -u root -e "SELECT user,authentication_string,plugin,host FROM mysql.user;"
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
