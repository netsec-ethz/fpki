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
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
EOF
)
echo "$CMD" | mysql -u root


CMD=$(cat <<EOF
USE fpki;
DROP TABLE IF EXISTS root;
-- the root table should contain only one record: the root node
CREATE TABLE root (
  leftnode    VARBINARY(33) DEFAULT NULL,
  rightnode   VARBINARY(33) DEFAULT NULL,
  value       blob,
  proof       VARBINARY(32) DEFAULT NULL
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
EOF
)
echo "$CMD" | mysql -u root


CMD=$(cat <<EOF
USE fpki;
DROP TABLE IF EXISTS leaves;
CREATE TABLE leaves (
  idhash      VARBINARY(32) NOT NULL,
  value       BLOB DEFAULT NULL,
  proof       BLOB DEFAULT NULL,
  autoid      BIGINT NOT NULL AUTO_INCREMENT,
  PRIMARY KEY(autoid),
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
USE fpki;
DROP PROCEDURE IF EXISTS flatten_subtree;

DELIMITER $$
-- recursive procedure that flattens a subtree into simple leaf records
CREATE PROCEDURE flatten_subtree(
	IN nodeid VARBINARY(33),
	IN proofchain BLOB
)
BEGIN
		DECLARE xleft  VARBINARY(33);
        DECLARE xright VARBINARY(33);
        DECLARE xproof BLOB;
        DECLARE xvalue BLOB;

	SELECT leftnode,rightnode,proof,value INTO xleft,xright,xproof,xvalue FROM nodes WHERE idhash=nodeid;
    -- SELECT HEX(LEFT(nodeid, 1)),HEX(xproof);
	IF LEFT(nodeid, 1) = UNHEX("FF") THEN
		-- this is a leaf. End recursion
        REPLACE INTO leaves(idhash,proof,value) VALUES (RIGHT(nodeid,32), CONCAT(proofchain,xproof),xvalue);
        -- SET proofchain = CONCAT(proofchain,xproof);
    ELSE
		-- this is an intermediate node
		IF xleft IS NOT NULL THEN
			CALL flatten_subtree(xleft,CONCAT(proofchain,xproof));
		END IF;
		IF xright IS NOT NULL THEN
			CALL flatten_subtree(xright,CONCAT(proofchain,xproof));
		END IF;
	END IF;
END$$
DELIMITER ;

USE fpki;
DROP PROCEDURE IF EXISTS create_leaves;

DELIMITER $$
CREATE PROCEDURE create_leaves()
BEGIN
		DECLARE xleft  VARBINARY(33);
        DECLARE xright VARBINARY(33);
        DECLARE xproof BLOB;

	SELECT leftnode,rightnode,proof INTO xleft,xright,xproof FROM root;
	TRUNCATE leaves;
    -- OPTIMIZE TABLE leaves;
    SET autocommit=0;

    CALL flatten_subtree(xleft,xproof);
    CALL flatten_subtree(xright,xproof);
    COMMIT;
END$$
DELIMITER ;
EOF
)
echo "$CMD" | mysql -u root