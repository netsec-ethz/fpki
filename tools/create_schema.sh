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

MYSQLCMD="mysql -u root"

CMD=$(cat <<EOF
DROP DATABASE IF EXISTS fpki;
CREATE DATABASE fpki /*!40100 DEFAULT CHARACTER SET binary */ /*!80016 DEFAULT ENCRYPTION='N' */;
EOF
)
echo "$CMD" | mysql -u root


# CMD=$(cat <<EOF
# USE fpki;
# CREATE TABLE certs (
#   id VARBINARY(32) NOT NULL,
#   payload LONGBLOB,
#   parent VARBINARY(32) DEFAULT NULL,
#   PRIMARY KEY (id)
# ) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
# EOF
# )
# echo "$CMD" | mysql -u root

CMD=$(cat <<EOF
USE fpki;
CREATE TABLE certs (
  N BIGINT NOT NULL AUTO_INCREMENT,
  id VARBINARY(32) NOT NULL,
  payload LONGBLOB,
  parent VARBINARY(32) DEFAULT NULL,
  PRIMARY KEY (N),
  UNIQUE KEY (id)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
EOF
)
echo "$CMD" | mysql -u root



CMD=$(cat <<EOF
USE fpki;
CREATE TABLE domains (
  cert_id VARBINARY(32) NOT NULL,
  domain_id VARBINARY(32) NOT NULL,
  domain VARCHAR(300) COLLATE ascii_bin DEFAULT NULL,
  payload_id BIGINT,
  PRIMARY KEY (cert_id,domain_id)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
EOF
)
echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE fpki;
CREATE TABLE domain_payloads (
  id BIGINT NOT NULL AUTO_INCREMENT,
  payload LONGBLOB,
  payload_hash VARBINARY(32) DEFAULT NULL,
  PRIMARY KEY (id)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
EOF
)
echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE fpki;
CREATE TABLE dirty (
  id VARBINARY(32) NOT NULL,
  PRIMARY KEY (id)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
EOF
)
echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE fpki;
CREATE TABLE root (
  key32 VARBINARY(32) NOT NULL,
  PRIMARY KEY (key32)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
EOF
)
echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE fpki;
CREATE TABLE tree (
  key32 VARBINARY(32) NOT NULL,
  value longblob NOT NULL,
  id BIGINT NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (id),
  UNIQUE KEY key_UNIQUE (key32)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
EOF
)
echo "$CMD" | mysql -u root



# CMD=$(cat <<EOF
# USE fpki;
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
# echo "$CMD" | mysql -u root


# TODO(juagargi) delete

CMD=$(cat <<EOF
CREATE TABLE \`fpki\`.\`domainEntries\` (
   \`key\` VARBINARY(32) NOT NULL,
   \`value\` LONGBLOB NOT NULL,
   UNIQUE INDEX \`key_UNIQUE\` (\`key\` ASC));
EOF
)
echo "$CMD" | $MYSQLCMD


CMD=$(cat <<EOF
USE fpki;
CREATE TABLE updates (
  id VARBINARY(32) NOT NULL,
  PRIMARY KEY (id)
) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
EOF
)
echo "$CMD" | $MYSQLCMD

