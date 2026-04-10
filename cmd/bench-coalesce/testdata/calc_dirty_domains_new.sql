CREATE PROCEDURE calc_dirty_domains(
	IN partition_number INT,
	IN chunk_size INT,
	OUT processed_rows BIGINT
)
proc: BEGIN
	DECLARE EXIT HANDLER FOR SQLEXCEPTION
	BEGIN
		ROLLBACK;
		DROP TEMPORARY TABLE IF EXISTS temp_dirty_chunk;
		DROP TEMPORARY TABLE IF EXISTS temp_dirty_chunk_cert;
		DROP TEMPORARY TABLE IF EXISTS temp_dirty_chunk_policy;
		DROP TEMPORARY TABLE IF EXISTS temp_dirty_chunk_final;
		DROP TEMPORARY TABLE IF EXISTS temp_dirty_chunk_result;
		RESIGNAL;
	END;

	SET group_concat_max_len = 1073741824;
	SET processed_rows = 0;

	DROP TEMPORARY TABLE IF EXISTS temp_dirty_chunk;
	DROP TEMPORARY TABLE IF EXISTS temp_dirty_chunk_cert;
	DROP TEMPORARY TABLE IF EXISTS temp_dirty_chunk_policy;
	DROP TEMPORARY TABLE IF EXISTS temp_dirty_chunk_final;
	DROP TEMPORARY TABLE IF EXISTS temp_dirty_chunk_result;
	CREATE TEMPORARY TABLE temp_dirty_chunk (
		domain_id VARBINARY(32) NOT NULL,
		PRIMARY KEY(domain_id)
	) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
	CREATE TEMPORARY TABLE temp_dirty_chunk_cert (
		domain_id VARBINARY(32) NOT NULL,
		PRIMARY KEY(domain_id)
	) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
	CREATE TEMPORARY TABLE temp_dirty_chunk_policy (
		domain_id VARBINARY(32) NOT NULL,
		PRIMARY KEY(domain_id)
	) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
	CREATE TEMPORARY TABLE temp_dirty_chunk_final (
		domain_id VARBINARY(32) NOT NULL,
		PRIMARY KEY(domain_id)
	) ENGINE=InnoDB CHARSET=binary COLLATE=binary;
	CREATE TEMPORARY TABLE temp_dirty_chunk_result (
		domain_id VARBINARY(32) NOT NULL,
		cert_ids LONGBLOB,
		cert_ids_id VARBINARY(32) DEFAULT NULL,
		policy_ids LONGBLOB,
		policy_ids_id VARBINARY(32) DEFAULT NULL,
		PRIMARY KEY(domain_id)
	) ENGINE=InnoDB CHARSET=binary COLLATE=binary;

	SET @claim_sql = CONCAT("
		INSERT INTO temp_dirty_chunk(domain_id)
		SELECT domain_id
		FROM dirty PARTITION(p", partition_number, ")
		WHERE coalesced = FALSE
		ORDER BY domain_id
		LIMIT ", chunk_size
	);
	PREPARE stmt FROM @claim_sql;
	EXECUTE stmt;
	DEALLOCATE PREPARE stmt;

	INSERT INTO temp_dirty_chunk_cert(domain_id)
	SELECT domain_id FROM temp_dirty_chunk;
	INSERT INTO temp_dirty_chunk_policy(domain_id)
	SELECT domain_id FROM temp_dirty_chunk;
	INSERT INTO temp_dirty_chunk_final(domain_id)
	SELECT domain_id FROM temp_dirty_chunk;

	SELECT COUNT(*) INTO processed_rows FROM temp_dirty_chunk;
	IF processed_rows = 0 THEN
		DROP TEMPORARY TABLE IF EXISTS temp_dirty_chunk;
		DROP TEMPORARY TABLE IF EXISTS temp_dirty_chunk_cert;
		DROP TEMPORARY TABLE IF EXISTS temp_dirty_chunk_policy;
		DROP TEMPORARY TABLE IF EXISTS temp_dirty_chunk_final;
		DROP TEMPORARY TABLE IF EXISTS temp_dirty_chunk_result;
		LEAVE proc;
	END IF;

	START TRANSACTION;

	SET @compute_sql = CONCAT("
		INSERT INTO temp_dirty_chunk_result(
			domain_id,
			cert_ids,
			cert_ids_id,
			policy_ids,
			policy_ids_id
		)
		WITH RECURSIVE
		cert_closure AS (
			SELECT d.domain_id, c.cert_id, c.parent_id
			FROM temp_dirty_chunk_cert AS d
			INNER JOIN domain_certs AS dc ON dc.domain_id = d.domain_id
			INNER JOIN certs AS c ON c.cert_id = dc.cert_id
			UNION ALL
			SELECT cc.domain_id, c.cert_id, c.parent_id
			FROM cert_closure AS cc
			INNER JOIN certs AS c ON c.cert_id = cc.parent_id
		),
		cert_agg AS (
			SELECT domain_id, GROUP_CONCAT(cert_id ORDER BY cert_id SEPARATOR '') AS cert_ids
			FROM (
				SELECT DISTINCT domain_id, cert_id
				FROM cert_closure
			) AS cert_ids_per_domain
			GROUP BY domain_id
		),
		policy_closure AS (
			SELECT d.domain_id, p.policy_id, p.parent_id
			FROM temp_dirty_chunk_policy AS d
			INNER JOIN domain_policies AS dp ON dp.domain_id = d.domain_id
			INNER JOIN policies AS p ON p.policy_id = dp.policy_id
			UNION ALL
			SELECT pc.domain_id, p.policy_id, p.parent_id
			FROM policy_closure AS pc
			INNER JOIN policies AS p ON p.policy_id = pc.parent_id
		),
		policy_agg AS (
			SELECT domain_id, GROUP_CONCAT(policy_id ORDER BY policy_id SEPARATOR '') AS policy_ids
			FROM (
				SELECT DISTINCT domain_id, policy_id
				FROM policy_closure
			) AS policy_ids_per_domain
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
		FROM temp_dirty_chunk_final AS d
		LEFT JOIN cert_agg AS ca ON ca.domain_id = d.domain_id
		LEFT JOIN policy_agg AS pa ON pa.domain_id = d.domain_id
	");
	PREPARE stmt FROM @compute_sql;
	EXECUTE stmt;
	DEALLOCATE PREPARE stmt;

	SET @replace_sql = CONCAT("
		REPLACE INTO domain_payloads(domain_id, cert_ids, cert_ids_id, policy_ids, policy_ids_id)
		SELECT domain_id, cert_ids, cert_ids_id, policy_ids, policy_ids_id
		FROM temp_dirty_chunk_result
		WHERE cert_ids IS NOT NULL OR policy_ids IS NOT NULL
	");
	PREPARE stmt FROM @replace_sql;
	EXECUTE stmt;
	DEALLOCATE PREPARE stmt;

	SET @delete_payloads_sql = CONCAT("
		DELETE dp
		FROM domain_payloads PARTITION(p", partition_number, ") AS dp
		INNER JOIN temp_dirty_chunk_result AS r
			ON dp.domain_id = r.domain_id
		WHERE r.cert_ids IS NULL AND r.policy_ids IS NULL
	");
	PREPARE stmt FROM @delete_payloads_sql;
	EXECUTE stmt;
	DEALLOCATE PREPARE stmt;

	SET @delete_domains_sql = CONCAT("
		DELETE dom
		FROM domains PARTITION(p", partition_number, ") AS dom
		INNER JOIN temp_dirty_chunk_result AS r
			ON dom.domain_id = r.domain_id
		WHERE r.cert_ids IS NULL AND r.policy_ids IS NULL
	");
	PREPARE stmt FROM @delete_domains_sql;
	EXECUTE stmt;
	DEALLOCATE PREPARE stmt;

	SET @mark_coalesced_sql = CONCAT("
		UPDATE dirty PARTITION(p", partition_number, ") AS d
		INNER JOIN temp_dirty_chunk AS t ON d.domain_id = t.domain_id
		SET d.coalesced = TRUE
	");
	PREPARE stmt FROM @mark_coalesced_sql;
	EXECUTE stmt;
	DEALLOCATE PREPARE stmt;

	COMMIT;
	DROP TEMPORARY TABLE IF EXISTS temp_dirty_chunk;
	DROP TEMPORARY TABLE IF EXISTS temp_dirty_chunk_cert;
	DROP TEMPORARY TABLE IF EXISTS temp_dirty_chunk_policy;
	DROP TEMPORARY TABLE IF EXISTS temp_dirty_chunk_final;
	DROP TEMPORARY TABLE IF EXISTS temp_dirty_chunk_result;
END
