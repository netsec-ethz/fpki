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
  auto_id BIGINT NOT NULL AUTO_INCREMENT,
  domain_id VARBINARY(32) NOT NULL,
  domain_name VARCHAR(300) COLLATE ascii_bin DEFAULT NULL,

  PRIMARY KEY (auto_id),
  UNIQUE KEY(domain_id),
  INDEX domain_name (domain_name)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
CREATE TABLE certs (
  auto_id BIGINT NOT NULL AUTO_INCREMENT,
  cert_id VARBINARY(32) NOT NULL,
  parent_id VARBINARY(32) DEFAULT NULL,
  expiration DATETIME NOT NULL,
  payload LONGBLOB,

  PRIMARY KEY(auto_id),
  UNIQUE KEY(cert_id)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
CREATE TABLE domain_certs (
  auto_id BIGINT NOT NULL AUTO_INCREMENT,
  domain_id VARBINARY(32) NOT NULL,
  cert_id VARBINARY(32) NOT NULL,

  PRIMARY KEY(auto_id),
  UNIQUE KEY domain_cert (domain_id,cert_id),
  INDEX domain_id (domain_id)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
CREATE TABLE policies (
  auto_id BIGINT NOT NULL AUTO_INCREMENT,
  policy_id VARBINARY(32) NOT NULL,
  parent_id VARBINARY(32) DEFAULT NULL,
  expiration DATETIME NOT NULL,
  payload LONGBLOB,

  PRIMARY KEY(auto_id),
  UNIQUE KEY(policy_id)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
CREATE TABLE domain_policies (
  auto_id BIGINT NOT NULL AUTO_INCREMENT,
  domain_id VARBINARY(32) NOT NULL,
  policy_id VARBINARY(32) NOT NULL,

  PRIMARY KEY(auto_id),
  UNIQUE KEY domain_pol (domain_id,policy_id),
  INDEX domain_id (domain_id)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
CREATE TABLE domain_payloads (
  domain_id VARBINARY(32) NOT NULL,
  cert_ids LONGBLOB,                            -- IDs of each certificate for this domain,
                                                -- alphabetically sorted, one after another.
  cert_ids_id VARBINARY(32) DEFAULT NULL,       -- ID of cert_ids (above).
  policy_ids LONGBLOB,                          -- IDs of each policy object for this domain,
                                                -- alphabetically sorted, glued together.
  policy_ids_id VARBINARY(32) DEFAULT NULL,     -- ID of cert_ids (above).

  PRIMARY KEY (domain_id)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
CREATE TABLE dirty (
  auto_id BIGINT NOT NULL AUTO_INCREMENT,
  domain_id VARBINARY(32) NOT NULL,

  PRIMARY KEY (auto_id),
  UNIQUE KEY(domain_id)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
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
  size INTEGER,
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
CREATE PROCEDURE calc_dirty_domains()
BEGIN

	SET group_concat_max_len = 1073741824; -- so that GROUP_CONCAT doesn't truncate results
	-- Replace the domain ID, its certificates, policies, and their corresponding SHA256 for all dirty domains.
	REPLACE INTO domain_payloads(domain_id, cert_ids, cert_ids_id, policy_ids, policy_ids_id) -- Values from subquery.
	SELECT domain_id, cert_ids, UNHEX(SHA2(cert_ids, 256)) AS cert_ids_id, policy_ids, UNHEX(SHA2(policy_ids, 256)) AS policy_ids_id FROM -- Subquery to compute the SHA256 in place.
	(

	SELECT A.domain_id,GROUP_CONCAT(cert_id ORDER BY cert_id SEPARATOR '') AS cert_ids,GROUP_CONCAT(policy_id ORDER BY policy_id SEPARATOR '') AS policy_ids FROM
		(
			WITH RECURSIVE cte AS (
				-- Base case: specify which leaf certs we choose: those that
				-- have a link with a domain that is part of the dirty domains.
				SELECT dirty.domain_id, certs.cert_id, parent_id
				FROM certs
				INNER JOIN domain_certs ON certs.cert_id = domain_certs.cert_id
				INNER JOIN dirty ON domain_certs.domain_id = dirty.domain_id
				UNION ALL
				-- Recursive case: any certificate that has its ID as
				-- parent ID of the previous set, recursively.
				SELECT cte.domain_id, certs.cert_id, certs.parent_id
				FROM certs
				JOIN cte ON certs.cert_id = cte.parent_id
			)
			SELECT DISTINCT domain_id, cert_id FROM cte
		) AS A
	LEFT OUTER JOIN
		(
			WITH RECURSIVE cte AS (
				-- Base case: specify which leaf policies we choose: those that
				-- have a link with a domain that is part of the dirty domains.
				SELECT dirty.domain_id, policies.policy_id, parent_id
				FROM policies
				INNER JOIN domain_policies ON policies.policy_id = domain_policies.policy_id
				INNER JOIN dirty ON domain_policies.domain_id = dirty.domain_id
				UNION ALL
				-- Recursive case: any poilicy that has its ID as
				-- parent ID of the previous set, recursively.
				SELECT cte.domain_id, policies.policy_id, policies.parent_id
				FROM policies
				JOIN cte ON policies.policy_id = cte.parent_id
			)
			SELECT DISTINCT domain_id, policy_id FROM cte
		) AS B
	ON A.domain_id = B.domain_id
	GROUP BY domain_id

	UNION

	SELECT B.domain_id,GROUP_CONCAT(cert_id ORDER BY cert_id SEPARATOR '') AS cert_ids,GROUP_CONCAT(policy_id ORDER BY policy_id SEPARATOR '') AS policy_ids FROM
		(
			WITH RECURSIVE cte AS (
				-- Base case: specify which leaf certs we choose: those that
				-- have a link with a domain that is part of the dirty domains.
				SELECT dirty.domain_id, certs.cert_id, parent_id
				FROM certs
				INNER JOIN domain_certs ON certs.cert_id = domain_certs.cert_id
				INNER JOIN dirty ON domain_certs.domain_id = dirty.domain_id
				UNION ALL
				-- Recursive case: any certificate that has its ID as
				-- parent ID of the previous set, recursively.
				SELECT cte.domain_id, certs.cert_id, certs.parent_id
				FROM certs
				JOIN cte ON certs.cert_id = cte.parent_id
			)
			SELECT DISTINCT domain_id, cert_id FROM cte
		) AS A
	RIGHT OUTER JOIN
		(
			WITH RECURSIVE cte AS (
				-- Base case: specify which leaf policies we choose: those that
				-- have a link with a domain that is part of the dirty domains.
				SELECT dirty.domain_id, policies.policy_id, parent_id
				FROM policies
				INNER JOIN domain_policies ON policies.policy_id = domain_policies.policy_id
				INNER JOIN dirty ON domain_policies.domain_id = dirty.domain_id
				UNION ALL
				-- Recursive case: any poilicy that has its ID as
				-- parent ID of the previous set, recursively.
				SELECT cte.domain_id, policies.policy_id, policies.parent_id
				FROM policies
				JOIN cte ON policies.policy_id = cte.parent_id
			)
			SELECT DISTINCT domain_id, policy_id FROM cte
		) AS B
	ON A.domain_id = B.domain_id
	GROUP BY domain_id

	) AS hasher_query;


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
	REPLACE INTO dirty(domain_id)
	SELECT DISTINCT domain_id FROM domain_certs WHERE cert_id IN (SELECT cert_id FROM temp_cert_ids);

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
  echo "This will destroy everything in the fpki database"
  read -p "Are you sure? (y/n) default=n " answer
  case ${answer:0:1} in
      y|Y )
      ;;
      * )
          exit 1
      ;;
  esac
  create_new_db fpki
fi

