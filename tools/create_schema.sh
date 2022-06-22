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
  proof       VARBINARY(32) DEFAULT NULL,
  UNIQUE KEY idhash (idhash)
) ENGINE=InnoDB CHARSET=\`binary\` COLLATE=\`binary\`;
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


CMD=$(cat <<EOF
USE fpki;
DROP PROCEDURE IF EXISTS val_and_proof_path;

DELIMITER $$
CREATE PROCEDURE val_and_proof_path(
	IN nodehash VARBINARY(33)
)
BEGIN
        DECLARE temp VARBINARY(33);
        DECLARE parent VARBINARY(33);
        DECLARE nodevalue BLOB;
		DECLARE proofs BLOB DEFAULT '';

SELECT value INTO nodevalue FROM nodes WHERE idhash = nodehash;

WHILE nodehash IS NOT NULL DO
	SELECT proof,parentnode INTO temp,parent FROM nodes WHERE idhash = nodehash;

    SET proofs = CONCAT(proofs,temp);
    SET nodehash = parent;
END WHILE;
    SELECT nodevalue,proofs;
END$$
DELIMITER ;
EOF
)
echo "$CMD" | mysql -u root



CMD=$(cat <<EOF
CREATE TABLE \`fpki\`.\`domainEntries\` (
   \`key\` VARBINARY(32) NOT NULL,
   \`value\` LONGBLOB NOT NULL,
   UNIQUE INDEX \`key_UNIQUE\` (\`key\` ASC));
EOF
)
echo "$CMD" | mysql -u root



CMD=$(cat <<EOF
CREATE TABLE \`fpki\`.\`tree\` (
   \`key\` VARBINARY(32) NOT NULL,
   \`value\` LONGBLOB NOT NULL,
   \`id\` BIGINT(64) NOT NULL AUTO_INCREMENT,
   PRIMARY KEY (\`id\`),
   UNIQUE INDEX \`key_UNIQUE\` (\`key\` ASC));
EOF
)
echo "$CMD" | mysql -u root



CMD=$(cat <<EOF
CREATE TABLE \`fpki\`.\`deleteTest\` (
   \`key\` VARCHAR(64) NOT NULL,
   \`value\` BLOB NOT NULL,
   \`id\` BIGINT(64) NOT NULL AUTO_INCREMENT,
    PRIMARY KEY (\`id\`),
   UNIQUE INDEX \`key_UNIQUE\` (\`key\` ASC));
EOF
)
echo "$CMD" | mysql -u root


CMD=$(cat <<EOF
  CREATE TABLE \`fpki\`.\`updates\` (
   \`key\` VARBINARY(32) NOT NULL,
   PRIMARY KEY (\`key\`));
EOF
)
echo "$CMD" | mysql -u root



