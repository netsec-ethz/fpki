#!/bin/bash


create_new_db() {
  set -e

  DBNAME=$1
  MYSQLCMD="mysql -u root"


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
  domain_name VARCHAR(300) COLLATE ascii_bin DEFAULT NULL,

  PRIMARY KEY (domain_id),
  INDEX domain_id (domain_id),
  INDEX domain_name (domain_name)
) ENGINE=MyISAM CHARSET=binary COLLATE=binary;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
CREATE TABLE certs (
  cert_id VARBINARY(32) NOT NULL,
  parent_id VARBINARY(32) DEFAULT NULL,
  expiration DATETIME NOT NULL,
  payload LONGBLOB,

  PRIMARY KEY(cert_id)
) ENGINE=MyISAM CHARSET=binary COLLATE=binary;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
CREATE TABLE domain_certs (
  domain_id VARBINARY(32) NOT NULL,
  cert_id VARBINARY(32) NOT NULL,

  PRIMARY KEY (domain_id,cert_id),
  INDEX domain_id (domain_id)
) ENGINE=MyISAM CHARSET=binary COLLATE=binary;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
CREATE TABLE policies (
  policy_id VARBINARY(32) NOT NULL,
  parent_id VARBINARY(32) DEFAULT NULL,
  expiration DATETIME NOT NULL,
  payload LONGBLOB,

  PRIMARY KEY(policy_id)
) ENGINE=MyISAM CHARSET=binary COLLATE=binary;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
CREATE TABLE domain_policies (
  domain_id VARBINARY(32) NOT NULL,
  policy_id VARBINARY(32) NOT NULL,

  PRIMARY KEY (domain_id,policy_id),
  INDEX domain_id (domain_id)
) ENGINE=MyISAM CHARSET=binary COLLATE=binary;
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
) ENGINE=MyISAM CHARSET=binary COLLATE=binary;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
CREATE TABLE dirty (
  domain_id VARBINARY(32) NOT NULL,

  PRIMARY KEY (domain_id)
) ENGINE=MyISAM CHARSET=binary COLLATE=binary;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
CREATE TABLE root (
  key32 VARBINARY(32) NOT NULL,

  PRIMARY KEY (key32)
) ENGINE=MyISAM CHARSET=binary COLLATE=binary;
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
) ENGINE=MyISAM CHARSET=binary COLLATE=binary;
EOF
  )
  echo "$CMD" | $MYSQLCMD


  CMD=$(cat <<EOF
USE $DBNAME;
DROP PROCEDURE IF EXISTS calc_dirty_domains;
DELIMITER $$
-- Because MySQL doesn't support FULL OUTER JOIN, we have to emulate it with:
-- SELECT * FROM t1
-- LEFT JOIN t2 ON t1.id = t2.id
-- UNION
-- SELECT * FROM t1
-- RIGHT JOIN t2 ON t1.id = t2.id
-- https://stackoverflow.com/questions/4796872/how-can-i-do-a-full-outer-join-in-mysql
--
-- The table t1 is a CTE that retrieves the certificates.
-- The table t2 is a CTE that retrieves the policies.
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

