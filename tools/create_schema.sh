#!/bin/bash

echo "This will destroy everything in the fpki database"


read -p "Are you sure? (y/n) default=n " answer
case ${answer:0:1} in
    y|Y )
    ;;
    * )
        exit 1
    ;;
esac

set -e # after call to read

CMD=$(cat <<EOF
DROP DATABASE IF EXISTS fpki;
CREATE DATABASE fpki /*!40100 DEFAULT CHARACTER SET ascii COLLATE ascii_bin */ /*!80016 DEFAULT ENCRYPTION='N' */;
EOF
)
echo "$CMD" | mysql -u root


CMD=$(cat <<EOF
USE fpki;
CREATE TABLE nodes (
  idhash      VARBINARY(33) NOT NULL,
  parentnode  VARBINARY(33) DEFAULT NULL,
  leftnode    VARBINARY(33) DEFAULT NULL,
  rightnode   VARBINARY(33) DEFAULT NULL,
  value       blob,
  UNIQUE KEY idhash (idhash)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
EOF
)
echo "$CMD" | mysql -u root


CMD=$(cat <<EOF
USE fpki;
DROP FUNCTION IF EXISTS node_path;

DELIMITER $$
CREATE FUNCTION node_path(
	nodehash VARBINARY(33)
)
RETURNS BLOB
DETERMINISTIC
BEGIN
		DECLARE hashes BLOB DEFAULT '';
        DECLARE temp VARBINARY(33);
        DECLARE parent VARBINARY(33);

WHILE nodehash IS NOT NULL DO
	SELECT idhash,parentnode INTO temp,parent FROM nodes WHERE idhash = nodehash;

    SET hashes = CONCAT(hashes,temp);
    SET nodehash = parent;
END WHILE;
    RETURN hashes;

END$$
DELIMITER ;
EOF
)
echo "$CMD" | mysql -u root


# CMD=$(cat <<EOF
# USE fpki;
# SELECT * FROM nodes LIMIT 2;
# EOF
# )

# echo "$CMD" | mysql -u root