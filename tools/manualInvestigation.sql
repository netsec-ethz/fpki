-- debug performance:
-- SHOW ENGINE INNODB STATUS;


-- Variables system wide:
-- /etc/sysctl.conf:
-- fs.aio-max-nr = 1048576

-- Variables that need to change in the mysql configuration file:
-- $ cat conf.d/fpki.cnf
-- # optimize fpki

-- [mysqld]

-- innodb_buffer_pool_size = 8589934592  # 8 GB
-- innodb_buffer_pool_instances = 64  # one per thread/connection

-- innodb_write_io_threads = 64
-- innodb_read_io_threads = 64

-- sync_binlog = 0  # disable syncing the binary log to disk (better performance). The kernel will flush it from time to time.

-- innodb_flush_method = "O_DIRECT"


-- important variables taken into account:

-- SHOW GLOBAL VARIABLES LIKE "max_sp_recursion_depth";  -- shoult be 255
-- SHOW GLOBAL VARIABLES LIKE "innodb_file_per_table"; -- should be "ON"
-- SHOW GLOBAL VARIABLES LIKE "innodb_write_io_threads";
-- SHOW GLOBAL VARIABLES LIKE "innodb_read_io_threads";
-- SHOW GLOBAL VARIABLES LIKE "sync_binlog"; -- should be 0 (no sync)
-- SHOW GLOBAL VARIABLES LIKE "innodb_buffer_pool_size";
-- SHOW GLOBAL VARIABLES LIKE "innodb_thread_concurrency"; -- should be 0 (no limit)
-- SHOW GLOBAL VARIABLES LIKE "innodb_log_buffer_size";
-- maybe set the IO scheduler to deadline. Difference of < 1% with an SSD
-- SHOW GLOBAL VARIABLES LIKE "innodb_flush_method";  -- should be O_DIRECT
-- SHOW GLOBAL VARIABLES LIKE "innodb_use_fdatasync"; -- should be ON
-- SHOW GLOBAL VARIABLES LIKE "innodb_use_native_aio";   -- should be ON
-- SHOW GLOBAL VARIABLES LIKE "innodb_table_locks"; -- should be 0 (don't lock tables with autocommit=0)
-- SHOW GLOBAL VARIABLES LIKE "innodb_flush_log_at_trx_commit";  -- doesn't help

-- Test table used to test parallel inserts performance:

USE fpki;
DROP TABLE IF EXISTS test;
CREATE TABLE test (
  autoid      BIGINT NOT NULL AUTO_INCREMENT,
  idhash      VARBINARY(32) NOT NULL,
  id          BIGINT NOT NULL,
  value       BLOB DEFAULT NULL,
  proof       BLOB DEFAULT NULL,
  -- UNIQUE KEY idhash (idhash),
  -- UNIQUE KEY id (id)
  PRIMARY KEY(autoid)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;






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
--   UNIQUE KEY idhash (idhash)
  autoid      BIGINT NOT NULL AUTO_INCREMENT,
  PRIMARY KEY(autoid)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;


-- Create a new index on the leaves table after computing the leaves:
USE fpki;
ALTER TABLE leaves
ADD UNIQUE INDEX idhash (idhash ASC);
;





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
        INSERT INTO leaves(idhash,proof,value) VALUES (RIGHT(nodeid,32), CONCAT(proofchain,xproof),xvalue);
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
	-- TODO(juagargi) obtain the values of the proofs for the left and right nodes
--     CALL flatten_subtree(UNHEX("000000000000000000000000000000000000000000000000000000000000000000"),''); -- left node
--     CALL flatten_subtree(UNHEX("008000000000000000000000000000000000000000000000000000000000000000"),''); -- right node
    COMMIT;
END$$
DELIMITER ;

SET max_sp_recursion_depth = 255;
CALL create_leaves();
