#!/bin/bash


create_new_db() {

set -e


DBNAME=$1

MYSQLCMD="mysql -u ${MYSQL_USER:-root}"
if [ -n "${MYSQL_PASSWORD}" ]; then
    MYSQLCMD="${MYSQLCMD} -p${MYSQL_PASSWORD}"
fi
if [ -n "${MYSQL_HOST}" ] || [ -n "${MYSQL_PORT}" ]; then
    MYSQLCMD="${MYSQLCMD} -h ${MYSQL_HOST:-localhost} -P ${MYSQL_PORT:-3306} --protocol TCP"
fi


CMD=$(cat <<EOF
DROP DATABASE IF EXISTS $DBNAME;
CREATE DATABASE $DBNAME /*!40100 DEFAULT CHARACTER SET binary */ /*!80016 DEFAULT ENCRYPTION='N' */;
EOF
  )
  echo "$CMD" | $MYSQLCMD



CMD=$(cat <<EOF
USE $DBNAME;
CREATE TABLE domains (
  domain_id VARBINARY(32) NOT NULL,
  shard TINYINT UNSIGNED AS
    (ORD(LEFT(domain_id, 1)) >> 3 ) STORED,
  domain_name VARCHAR(300) COLLATE ascii_bin DEFAULT NULL,

  PRIMARY KEY (domain_id,shard),
  INDEX domain_name (domain_name)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary
PARTITION BY HASH (shard) PARTITIONS 32;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
CREATE TABLE certs (
  cert_id VARBINARY(32) NOT NULL,
  shard TINYINT UNSIGNED AS
    (ORD(LEFT(cert_id, 1)) >> 3 ) STORED,
  parent_id VARBINARY(32) DEFAULT NULL,
  expiration DATETIME NOT NULL,
  payload LONGBLOB,

  PRIMARY KEY(cert_id,shard)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary
PARTITION BY HASH (shard) PARTITIONS 32;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
CREATE TABLE domain_certs (
  domain_id VARBINARY(32) NOT NULL,
  shard TINYINT UNSIGNED AS
    (ORD(LEFT(domain_id, 1)) >> 3 ) STORED,
  cert_id VARBINARY(32) NOT NULL,

  PRIMARY KEY domain_cert (domain_id,shard,cert_id),
  INDEX cert_id (cert_id)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary
PARTITION BY HASH (shard) PARTITIONS 32;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
CREATE TABLE policies (
  policy_id VARBINARY(32) NOT NULL,
  shard TINYINT UNSIGNED AS
    (ORD(LEFT(policy_id, 1)) >> 3 ) STORED,
  parent_id VARBINARY(32) DEFAULT NULL,
  expiration DATETIME NOT NULL,
  payload LONGBLOB,

  PRIMARY KEY(policy_id,shard)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary
PARTITION BY HASH (shard) PARTITIONS 32;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
CREATE TABLE domain_policies (
  domain_id VARBINARY(32) NOT NULL,
  shard TINYINT UNSIGNED AS
    (ORD(LEFT(domain_id, 1)) >> 3 ) STORED,
  policy_id VARBINARY(32) NOT NULL,

  PRIMARY KEY domain_pol (domain_id,shard,policy_id),
  INDEX policy_id (policy_id)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary
PARTITION BY HASH (shard) PARTITIONS 32;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
CREATE TABLE domain_payloads (
  domain_id VARBINARY(32) NOT NULL,
  shard TINYINT UNSIGNED AS
    (ORD(LEFT(domain_id, 1)) >> 3 ) STORED,
  cert_ids LONGBLOB,                            -- IDs of each certificate for this domain,
                                                -- alphabetically sorted, one after another.
  cert_ids_id VARBINARY(32) DEFAULT NULL,       -- ID of cert_ids (above).
  policy_ids LONGBLOB,                          -- IDs of each policy object for this domain,
                                                -- alphabetically sorted, glued together.
  policy_ids_id VARBINARY(32) DEFAULT NULL,     -- ID of cert_ids (above).

  PRIMARY KEY (domain_id,shard)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary
PARTITION BY HASH (shard) PARTITIONS 32;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
CREATE TABLE dirty (
  domain_id VARBINARY(32) NOT NULL,
  shard TINYINT UNSIGNED AS
    (ORD(LEFT(domain_id, 1)) >> 3 ) STORED,
  coalesced BOOLEAN NOT NULL DEFAULT FALSE,

  PRIMARY KEY(domain_id,shard),
  INDEX dirty_coalesced (coalesced)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary
PARTITION BY HASH (shard) PARTITIONS 32;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
CREATE TABLE root (
    key32 VARBINARY(32) NOT NULL,

    -- constraints to ensure that only a single root value exists at any time by having a single possible value for the primary key
    single_row_pk char(25) NOT NULL PRIMARY KEY DEFAULT 'PK_RestrictToOneRootValue' CHECK (single_row_pk='PK_RestrictToOneRootValue')
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
-- Stores the last valid status that was ingested, per CT log server URL
CREATE TABLE ctlog_server_last_status (
  url_hash VARBINARY(32) NOT NULL,
  size BIGINT,
  sth BLOB,

  PRIMARY KEY (url_hash)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
CREATE TABLE tree (
  key32 VARBINARY(32) NOT NULL,
  value longblob NOT NULL,
  id BIGINT NOT NULL AUTO_INCREMENT,

  PRIMARY KEY (id),
  UNIQUE KEY key_UNIQUE (key32)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
DROP PROCEDURE IF EXISTS calc_dirty_domains;
DELIMITER $$
-- The procedure has one argument: the partition number to operate on. Usually 0..31.
-- Because MySQL doesn't support FULL OUTER JOIN, we have to emulate it.
-- We want:
-- SELECT * FROM t1
-- FULL OUTER JOIN
-- SELECT * FROM t2
-- ------------------------------------
-- We emulate is with:
-- SELECT * FROM t1
-- LEFT JOIN t2 ON t1.id = t2.id
-- UNION
-- SELECT * FROM t1
-- RIGHT JOIN t2 ON t1.id = t2.id
-- https://stackoverflow.com/questions/4796872/how-can-i-do-a-full-outer-join-in-mysql
--
-- The table t1 is a CTE that retrieves the certificates.
-- The table t2 is a CTE that retrieves the policies.
-- ------------------------------------
-- This SP needs ~ 5 seconds per 20K dirty domains.
CREATE PROCEDURE calc_dirty_domains(
    IN partition_number INT,
	IN chunk_size INT,
	OUT processed_rows BIGINT
)
proc: BEGIN

    SET group_concat_max_len = 1073741824; -- so that GROUP_CONCAT doesn't truncate results

    SET processed_rows = 0;

    SET @count_sql = CONCAT("
		SELECT COUNT(*) INTO @chunk_rows
		FROM (
			SELECT domain_id
			FROM dirty PARTITION(p", partition_number, ") FORCE INDEX (dirty_coalesced)
			WHERE coalesced = FALSE
			ORDER BY shard,coalesced,domain_id
			LIMIT ", chunk_size, "
		) AS chunk_domains
	");
	PREPARE stmt FROM @count_sql;
	EXECUTE stmt;
	DEALLOCATE PREPARE stmt;

	SET processed_rows = COALESCE(@chunk_rows, 0);
	IF processed_rows = 0 THEN
		LEAVE proc;
	END IF;

    SET TRANSACTION ISOLATION LEVEL READ COMMITTED;

    SET @replace_sql = CONCAT("
    REPLACE INTO domain_payloads PARTITION(p", partition_number, ") (
			domain_id,
			cert_ids,
			cert_ids_id,
			policy_ids,
			policy_ids_id
		)
		WITH RECURSIVE

		chunk_domains AS (
			SELECT domain_id
			FROM dirty PARTITION(p", partition_number, ")
			FORCE INDEX (dirty_coalesced)
			WHERE coalesced = FALSE
			ORDER BY coalesced,domain_id
			LIMIT ", chunk_size, "
		),
		cert_closure AS (
			SELECT d.domain_id, c.cert_id, c.parent_id
			FROM chunk_domains AS d
			INNER JOIN domain_certs AS dc ON dc.domain_id = d.domain_id
			INNER JOIN certs AS c ON c.cert_id = dc.cert_id

			UNION

			SELECT cc.domain_id, c.cert_id, c.parent_id
			FROM cert_closure AS cc
			INNER JOIN certs AS c ON c.cert_id = cc.parent_id
		),
        cert_agg AS (
			SELECT domain_id, GROUP_CONCAT(cert_id ORDER BY cert_id SEPARATOR '') AS cert_ids
			FROM cert_closure
			GROUP BY domain_id
		),
		policy_closure AS (
			SELECT d.domain_id, p.policy_id, p.parent_id
			FROM chunk_domains AS d
			INNER JOIN domain_policies AS dp ON dp.domain_id = d.domain_id
			INNER JOIN policies AS p ON p.policy_id = dp.policy_id

			UNION

			SELECT pc.domain_id, p.policy_id, p.parent_id
			FROM policy_closure AS pc
			INNER JOIN policies AS p ON p.policy_id = pc.parent_id
		),
		policy_agg AS (
			SELECT domain_id, GROUP_CONCAT(policy_id ORDER BY policy_id SEPARATOR '') AS policy_ids
			FROM policy_closure
			GROUP BY domain_id
		)
        SELECT
			d.domain_id,
			ca.cert_ids,
			CASE
				WHEN ca.cert_ids IS NULL THEN NULL
				ELSE UNHEX(SHA2(ca.cert_ids, 256))
			END AS cert_ids_id,
			pa.policy_ids,
			CASE
				WHEN pa.policy_ids IS NULL THEN NULL
				ELSE UNHEX(SHA2(pa.policy_ids, 256))
			END AS policy_ids_id
		FROM chunk_domains AS d
		LEFT JOIN cert_agg AS ca ON ca.domain_id = d.domain_id
		LEFT JOIN policy_agg AS pa ON pa.domain_id = d.domain_id
    ");
	PREPARE stmt FROM @replace_sql;
	EXECUTE stmt;
	DEALLOCATE PREPARE stmt;

    SET @delete_payloads_sql = CONCAT("
        DELETE dp
        FROM domain_payloads PARTITION(p", partition_number, ") AS dp
        INNER JOIN (
            SELECT shard, domain_id
            FROM dirty PARTITION(p", partition_number, ")
			FORCE INDEX (dirty_coalesced)
			WHERE coalesced = FALSE
			ORDER BY coalesced,domain_id
            LIMIT ", chunk_size, "
        ) AS d
        ON dp.shard = d.shard AND dp.domain_id = d.domain_id
        WHERE dp.cert_ids IS NULL
        AND dp.policy_ids IS NULL
    ");
    PREPARE stmt FROM @delete_payloads_sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;

    SET @delete_domains_sql = CONCAT("
        DELETE dom
        FROM domains PARTITION(p", partition_number, ") AS dom
        INNER JOIN (
            SELECT shard,domain_id
            FROM dirty PARTITION(p", partition_number, ")
			FORCE INDEX (dirty_coalesced)
			WHERE coalesced = FALSE
			ORDER BY coalesced,domain_id
            LIMIT ", chunk_size, "
        ) AS d
        ON dom.shard = d.shard AND dom.domain_id = d.domain_id
        LEFT JOIN domain_payloads PARTITION(p", partition_number, ") AS dp
            ON dp.shard = dom.shard AND dp.domain_id = dom.domain_id
        WHERE dp.domain_id IS NULL;
    ");
    PREPARE stmt FROM @delete_domains_sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;

    SET @mark_coalesced_sql = CONCAT("
		UPDATE dirty PARTITION(p", partition_number, ") AS d
		INNER JOIN (
			SELECT shard, domain_id
            FROM dirty PARTITION(p", partition_number, ")
			FORCE INDEX (dirty_coalesced)
			WHERE coalesced = FALSE
			ORDER BY coalesced,domain_id
            LIMIT ", chunk_size, "
		) AS t
        ON d.shard = t.shard AND d.domain_id = t.domain_id
		SET d.coalesced = TRUE
	");
	PREPARE stmt FROM @mark_coalesced_sql;
	EXECUTE stmt;
	DEALLOCATE PREPARE stmt;


END$$
DELIMITER ;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
DROP PROCEDURE IF EXISTS prune_expired;
DELIMITER $$
-- The procedure has one parameter, the time considered "cut".
-- Any x509 certificate that expires before that time will be removed.
-- Any removed certificate will also trigger the removal of its descendants.
-- Any domain which had a certificate pruned will be added to the "dirty" list.
CREATE PROCEDURE prune_expired(IN cut DATETIME)
BEGIN

	-- Create a temporary table to hold the IDs of all the expired certs or descendants.
	CREATE TEMPORARY TABLE temp_cert_ids (
	  cert_id VARBINARY(32)
	);

	-- Insert the IDs of expired certificates or their descendants into the temporary table.
	INSERT INTO temp_cert_ids(cert_id)
	SELECT cert_id FROM
	(
		WITH RECURSIVE expired_and_descendants AS (
			-- Base case: Select all expired certificates
			SELECT cert_id
			FROM certs
			WHERE expiration < cut
			UNION ALL
			-- Recursive case: Join the above result with certs on parent_id to get descendants
			SELECT c.cert_id
			FROM certs c
			INNER JOIN expired_and_descendants ead ON c.parent_id = ead.cert_id
		)
		SELECT cert_id FROM expired_and_descendants
	) AS exp_certs;

	-- Insert the domain IDs that had a certificate in the temporary table.
	REPLACE INTO dirty(domain_id, coalesced)
	SELECT DISTINCT domain_id, FALSE FROM domain_certs WHERE cert_id IN (SELECT cert_id FROM temp_cert_ids);

	-- Remove expired certificates
	DELETE FROM certs WHERE cert_id IN (SELECT cert_id FROM temp_cert_ids);

	-- Finally, remove temporary table
	DROP TEMPORARY TABLE temp_cert_ids;

END$$
DELIMITER ;
EOF
  )
  echo "$CMD" | $MYSQLCMD


} # end of `create_new_db` function



if [ "${BASH_SOURCE[0]}" -ef "$0" ]
then
  DBNAME="${1:-fpki}"
  echo "This will destroy everything in the ${DBNAME} database"
  read -p "Are you sure? (y/n) default=n " answer
  case ${answer:0:1} in
      y|Y )
      ;;
      * )
          exit 1
      ;;
  esac
  create_new_db "${DBNAME}"
fi
