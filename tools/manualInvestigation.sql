-- Some commands used during the investigation, for reference:

-- Queries

SELECT COUNT(*) FROM fpki.nodes;
SELECT HEX(idhash), HEX(value) FROM fpki.nodes;
SELECT HEX(idhash) FROM fpki.nodes limit 64;
EXPLAIN SELECT HEX(idhash), HEX(value) FROM fpki.nodes WHERE idhash=UNHEX("000000000000010000000000000000000000000000000000000000000004A769");

SHOW STATUS LIKE 'max_used_connections';
EXPLAIN SELECT * FROM nodes WHERE idhash=UNHEX('84076901FBBB89EB9027FDA991C99CB0B7B840C32F629311D789AA8EEE941515');
SHOW WARNINGS;
EXPLAIN nodes;
ANALYZE TABLE nodes;

SELECT HEX(idhash) FROM nodes WHERE LEFT(idhash, 1) = UNHEX("FF");
SELECT HEX(idhash) FROM nodes WHERE idhash=UNHEX('FF00008EE8B701BFCEE3D0F0ECC2D1FD183A363E01CC3347BC13446AE28CE4FD9D');


-- ---------------------------------------------
-- ---------------------------------------------
-- Create Schema and Tables

DROP DATABASE IF EXISTS fpki;
CREATE DATABASE fpki /*!40100 DEFAULT CHARACTER SET ascii COLLATE ascii_bin */ /*!80016 DEFAULT ENCRYPTION='N' */;


CREATE TABLE nodes (
  idhash      VARBINARY(33) NOT NULL,
  parentnode  VARBINARY(33) DEFAULT NULL,
  leftnode    VARBINARY(33) DEFAULT NULL,
  rightnode   VARBINARY(33) DEFAULT NULL,
  value       blob,
  UNIQUE KEY idhash (idhash)
  -- KEY idhash (idhash)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;


-- ---------------------------------------------
-- ---------------------------------------------
-- Create Stored Function

USE fpki;
DROP FUNCTION IF EXISTS node_path;

DELIMITER $$
CREATE FUNCTION node_path(
	nodehash VARBINARY(33)
)
RETURNS BLOB  -- the proof path (except the root), squashed into one blob.
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

-- SELECT HEX(node_path(UNHEX("FF00008EE8B701BFCEE3D0F0ECC2D1FD183A363E01CC3347BC13446AE28CE4FD9D")));


-- ---------------------------------------------
-- ---------------------------------------------
-- Create Stored Proc


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

-- CALL val_and_proof_path(UNHEX("FF00008EE8B701BFCEE3D0F0ECC2D1FD183A363E01CC3347BC13446AE28CE4FD9D"))



-- ---------------------------------------------
-- ---------------------------------------------
-- create leaves

DROP TABLE IF EXISTS leaves;
CREATE TABLE leaves (
  idhash      VARBINARY(32) NOT NULL,
  value       BLOB DEFAULT NULL,
  proof       BLOB DEFAULT NULL,
  UNIQUE KEY idhash (idhash)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;





USE fpki;
DROP PROCEDURE IF EXISTS _flatten_subtree;

DELIMITER $$
-- recursive procedure that flattens a subtree into simple leaf records
CREATE PROCEDURE _flatten_subtree(
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
        INSERT INTO leaves(idhash,proof,value) VALUES (RIGHT(nodeid,32), CONCAT(proofchain,xproof),xvalue);
        -- SET proofchain = CONCAT(proofchain,xproof);
    ELSE
		-- this is an intermediate node
		IF xleft IS NOT NULL THEN
			CALL _flatten_subtree(xleft,CONCAT(proofchain,xproof));
		END IF;
		IF xright IS NOT NULL THEN
			CALL _flatten_subtree(xright,CONCAT(proofchain,xproof));
		END IF;
	END IF;
END$$
DELIMITER ;

USE fpki;
DROP PROCEDURE IF EXISTS create_leaves;

DELIMITER $$
CREATE PROCEDURE create_leaves()
BEGIN
	TRUNCATE leaves;
    SET autocommit=0;
	-- TODO(juagargi) obtain the values of the proofs for the left and right nodes
    CALL _flatten_subtree(UNHEX("000000000000000000000000000000000000000000000000000000000000000000"),''); -- left node
    CALL _flatten_subtree(UNHEX("008000000000000000000000000000000000000000000000000000000000000000"),''); -- right node
    COMMIT;
END$$
DELIMITER ;

SET max_sp_recursion_depth = 255;
CALL create_leaves();
