# Develpment tools


## Installing the database

Based on [https://linuxhint.com/installing_mysql_workbench_ubuntu/](https://linuxhint.com/installing_mysql_workbench_ubuntu/).
- Download [mysql-apt-config](https://dev.mysql.com/downloads/repo/apt/) and install it with e.g. `sudo apt install mysql-apt-config_0.8.22-1_all.deb`.
- Select the version if the preselected one is not good.
- Install "mysql-server"
- Install "mysql-workbench-community"

To allow root without password:
- run `sudo mysql`
- enter `ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '';`
- enter `FLUSH PRIVILEGES;`
- you should see "mysql_native_password" as plugin for root when displaying the root user:
  `SELECT user,authentication_string,plugin,host FROM mysql.user;`

To allow mysqld reading from /tmp/ (load data infile) in ubuntu:
- Ubuntu runs apparmor. Edit `/etc/apparmor.d/usr.sbin.mysqld`
- After the line with `/usr/sbin/mysqld {`, insert a new line with `  /tmp/* r,`
- Reload apparmor `sudo systemctl reload apparmor.service`


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
