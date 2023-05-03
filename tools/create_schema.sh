#!/bin/bash


create_new_db() {
  set -e

  DBNAME=$1
  MYSQLCMD="mysql -u root"


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



# CMD=$(cat <<EOF
# USE $DBNAME;
# CREATE TABLE nodes (
#   idhash      VARBINARY(33) NOT NULL,
#   parentnode  VARBINARY(33) DEFAULT NULL,
#   leftnode    VARBINARY(33) DEFAULT NULL,
#   rightnode   VARBINARY(33) DEFAULT NULL,
#   value       blob,
#   proof       VARBINARY(32) DEFAULT NULL,
#   UNIQUE KEY idhash (idhash)
# ) ENGINE=InnoDB CHARSET=\`binary\` COLLATE=\`binary\`;
# EOF
  # )
  # echo "$CMD" | $MYSQLCMD


  # TODO(juagargi) delete

# TODO(juagargi) remove
CMD=$(cat <<EOF
CREATE TABLE \`$DBNAME\`.\`domainEntries\` (
  \`key\` VARBINARY(32) NOT NULL,
  \`value\` LONGBLOB NOT NULL,
  UNIQUE INDEX \`key_UNIQUE\` (\`key\` ASC));
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
CREATE TABLE updates (
  id VARBINARY(32) NOT NULL,
  PRIMARY KEY (id)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
EOF
  )
  echo "$CMD" | $MYSQLCMD


  CMD=$(cat <<EOF
USE $DBNAME;
DROP FUNCTION IF EXISTS IDsToSql;
DELIMITER $$
-- Receives a stream of IDs 32 bytes after another 32 bytes, etc.
-- Returns UNHEX("ID1_in_HEX"), UNHEX(........
CREATE FUNCTION IDsToSql( IDs LONGBLOB ) RETURNS LONGTEXT DETERMINISTIC
BEGIN
	SET @sql_ids = '';
	WHILE LENGTH(IDs) > 0 DO
		SET @id = LEFT(IDs, 32);
        SET IDs = RIGHT(IDs, LENGTH(IDs)-32);
        SET @sql_ids = CONCAT(@sql_ids, "UNHEX('", HEX(@id),"'),");
    END WHILE;
    -- Remove trailing comma.
    RETURN LEFT(@sql_ids, LENGTH(@sql_ids)-1);
END $$
DELIMITER ;
EOF
  )
  echo "$CMD" | $MYSQLCMD


  CMD=$(cat <<EOF
USE $DBNAME;
DROP PROCEDURE IF EXISTS cert_IDs_for_domain;
DELIMITER $$
-- Takes the domain IDs in binary, 32 bytes.
-- Returns the certificate IDs for that domain ID, in binary, all bytes glued together
-- (this is, 32 bytes, then 32 more, then ...).
CREATE PROCEDURE cert_IDs_for_domain( IN domainID LONGBLOB , OUT cert_ids LONGBLOB )
BEGIN
	SET group_concat_max_len = 1073741824; -- so that GROUP_CONCAT doesn't truncate results
	SELECT GROUP_CONCAT( DISTINCT cert_id SEPARATOR '')
    INTO @pending FROM domains WHERE domain_id = domainID;
    -- @pending contains now the list of cert IDs that are leaves.
    -- Keep retrieving parents until no more certs.
    SET @leaves = '';
    WHILE LENGTH(@pending) > 0 DO
		SET @leaves = CONCAT(@leaves, @pending);
		SET @str = CONCAT(
			"SELECT GROUP_CONCAT( DISTINCT parent_id SEPARATOR '' )
            INTO @pending FROM certs WHERE id IN (", IDsToSql(@pending), ");");
		PREPARE stmt FROM @str;
		EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END WHILE;
    -- Run a last query to get only the DISTINCT IDs, from all that we have in @leaves.
    SET @str = CONCAT(
		"SELECT GROUP_CONCAT( DISTINCT id SEPARATOR '' )
        INTO @leaves FROM certs WHERE id IN (", IDsToSql(@leaves), ");");
	PREPARE stmt FROM @str;
	EXECUTE stmt;
	DEALLOCATE PREPARE stmt;
    -- @leaves contains now all the certificate IDs in hexadecimal
    -- that are reachable from the domain names
    SET cert_ids = @leaves;
END $$
DELIMITER ;
EOF
  )
  echo "$CMD" | $MYSQLCMD


  CMD=$(cat <<EOF
USE $DBNAME;
DROP PROCEDURE IF EXISTS payloads_for_certs;
DELIMITER $$
-- Expects the cert_ids in binary, 32 bytes then 32 more, etc.
-- Returns the payload in binary.
CREATE PROCEDURE payloads_for_certs( IN cert_ids LONGBLOB , OUT payload LONGBLOB )
BEGIN
	SET group_concat_max_len = 1073741824; -- so that GROUP_CONCAT doesn't truncate results
	SET @str = CONCAT(
		"SELECT GROUP_CONCAT(payload SEPARATOR '') INTO @payload
		FROM certs WHERE id IN (", IDsToSql(cert_ids), ") ORDER BY expiration,payload;");
	PREPARE stmt FROM @str;
	EXECUTE stmt;
	DEALLOCATE PREPARE stmt;
    SET payload = @payload;
END$$
DELIMITER ;
EOF
  )
  echo "$CMD" | $MYSQLCMD


  CMD=$(cat <<EOF
USE $DBNAME;
DROP PROCEDURE IF EXISTS calc_several_domain_payloads;
DELIMITER $$
CREATE PROCEDURE calc_several_domain_payloads( IN domain_ids LONGBLOB )
BEGIN
	WHILE LENGTH(domain_ids) > 0 DO
		SET @id = LEFT(domain_ids, 32);
        SET domain_ids = RIGHT(domain_ids,LENGTH(domain_ids)-32);
        SET @certIDs = '';
        CALL cert_IDs_for_domain(@id, @certIDs);
        CALL payloads_for_certs(@certIDs, @payload);
        REPLACE INTO domain_payloads(domain_id, payload_id, payload) VALUES( @id, UNHEX(SHA2(@payload, 256)), @payload );
    END WHILE;
END$$
DELIMITER ;
EOF
  )
  echo "$CMD" | $MYSQLCMD

  CMD=$(cat <<EOF
USE $DBNAME;
DROP PROCEDURE IF EXISTS calc_some_dirty_domain_payloads;
DELIMITER $$
-- firstRow and lastRow are parameters specifying which is the first row of dirty,
-- and the last one for which it will update the payloads.
-- The SP needs ~ 5 seconds per 20K dirty domains.
CREATE PROCEDURE calc_some_dirty_domain_payloads( IN firstRow INT, IN lastRow INT )
BEGIN
		DECLARE numRows INT;

	SET group_concat_max_len = 1073741824; -- so that GROUP_CONCAT doesn't truncate results
	-- Replace the domain ID, its payload, and its SHA256 for a limitted subset of dirty domains.
	SET numRows = lastRow - firstRow +1;
	REPLACE INTO domain_payloads(domain_id, cert_ids, cert_ids_id) -- Values from subquery.
	SELECT domain_id, cert_ids, UNHEX(SHA2(cert_ids, 256)) FROM ( -- Subquery to compute the SHA256 in place.

		-- Select the concatenation of all cert IDs (sorted) or a domain.
		SELECT domain_id, GROUP_CONCAT(cert_id SEPARATOR '') AS cert_ids FROM(
		-- SELECT HEX(domain_id), HEX(cert_id) AS cert_ids FROM(
		-- The CTE lists all certs that are reachable by the domain_id
		WITH RECURSIVE cte AS (
			-- Base case: specify which leaf certs we choose: those that
			-- have a link with a domain that is part of the dirty domains.
			SELECT dirty.domain_id, certs.cert_id, parent_id
			FROM certs
			INNER JOIN domain_certs ON certs.cert_id = domain_certs.cert_id
			INNER JOIN dirty ON domain_certs.domain_id = dirty.domain_id
				WHERE dirty.domain_id IN (
					-- Forced to use an extra subquery due to mysql not being able
					-- to use LIMITs directly in a subquery. Wrapping in an extra
					-- subquery solves this.
					SELECT * FROM (
						SELECT domain_id FROM dirty
						ORDER BY domain_id
						LIMIT firstRow, numRows		-- Beware that mysql can only use SP variables here.
													-- https://bugs.mysql.com/bug.php?id=11918
					) AS limitter_query
				)

			UNION ALL
			-- Recursive case: any certificate that has its ID as
			-- parent ID of the previous set, recursively.
			SELECT cte.domain_id, certs.cert_id, certs.parent_id
			FROM certs
			JOIN cte ON certs.cert_id = cte.parent_id
		)
		SELECT DISTINCT domain_id, cert_id FROM cte ORDER BY cert_id
		) AS collate_cert_ids_query GROUP BY domain_id

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

