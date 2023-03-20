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
CREATE TABLE certs (
  id VARBINARY(32) NOT NULL,
  parent VARBINARY(32) DEFAULT NULL,
  expiration DATETIME NOT NULL,
  payload LONGBLOB,
  PRIMARY KEY(id)
) ENGINE=MyISAM CHARSET=binary COLLATE=binary;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
CREATE TABLE domains (
  cert_id VARBINARY(32) NOT NULL,
  domain_id VARBINARY(32) NOT NULL,
  domain_name VARCHAR(300) COLLATE ascii_bin DEFAULT NULL,
  PRIMARY KEY (cert_id,domain_id),
  INDEX domain_id (domain_id)
) ENGINE=MyISAM CHARSET=binary COLLATE=binary;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
CREATE TABLE domain_payloads (
  id VARBINARY(32) NOT NULL,
  payload LONGBLOB,
  payload_id VARBINARY(32) DEFAULT NULL,
  PRIMARY KEY (id)
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
DROP PROCEDURE IF EXISTS calc_domain_payload;
DELIMITER $$
  -- procedure that given a domain computes its payload and its SHA256 hash.
  CREATE PROCEDURE calc_domain_payload(
    IN domain_id VARBINARY(32)
  )
  BEGIN
      DECLARE payloadVar LONGBLOB;

    SET group_concat_max_len = 1073741824; -- so that GROUP_CONCAT doesn't truncate results
    -- Get all certificates for this domain.
    SELECT GROUP_CONCAT(payload SEPARATOR '') INTO payloadVar
      FROM certs INNER JOIN domains ON certs.id = domains.cert_id
      WHERE domains.domain_id = domain_id ORDER BY expiration,payload;
    REPLACE INTO domain_payloads(id, payload, payload_id) VALUES(domain_id,payloadVar,UNHEX(SHA2(payloadVar, 256)));
  END$$
DELIMITER ;
EOF
  )
  echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE $DBNAME;
DROP PROCEDURE IF EXISTS calc_several_domain_payloads;
DELIMITER $$
  CREATE PROCEDURE calc_several_domain_payloads(
    IN domain_ids LONGBLOB
  )
  BEGIN
      DECLARE IDS LONGBLOB;
          DECLARE ID VARBINARY(32);
    SET IDS = domain_ids;
    WHILE LENGTH(IDS) > 0 DO
      SET ID = LEFT(IDS,32);
      CALL calc_domain_payload(ID);
          SET IDS = RIGHT(IDS,LENGTH(IDS)-32);
      END WHILE;
  END$$
DELIMITER ;
EOF
  )
  echo "$CMD" | $MYSQLCMD
}

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

