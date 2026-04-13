CREATE PROCEDURE calc_dirty_domains(
	IN partition_number INT,
	IN chunk_size INT,
	OUT processed_rows BIGINT
)
proc: BEGIN
	DECLARE EXIT HANDLER FOR SQLEXCEPTION
	BEGIN
		ROLLBACK;
		RESIGNAL;
	END;

	SET group_concat_max_len = 1073741824;
	SET processed_rows = 0;

	SET @count_sql = CONCAT("
		SELECT COUNT(*) INTO @chunk_rows
		FROM (
			SELECT domain_id
			FROM dirty PARTITION(p", partition_number, ") FORCE INDEX (dirty_coalesced)
			WHERE coalesced = FALSE
			ORDER BY domain_id
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
	START TRANSACTION;

	SET @replace_sql = CONCAT("
		INSERT INTO domain_payloads PARTITION(p", partition_number, ") (
			domain_id,
			cert_ids,
			cert_ids_id,
			policy_ids,
			policy_ids_id
		)
		WITH RECURSIVE
		chunk_domains AS (
			SELECT domain_id
			FROM dirty PARTITION(p", partition_number, ") FORCE INDEX (dirty_coalesced)
			WHERE coalesced = FALSE
			ORDER BY domain_id
			LIMIT ", chunk_size, "
		),
		cert_closure AS (
			SELECT d.domain_id, c.cert_id, c.parent_id
			FROM chunk_domains AS d
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
			FROM chunk_domains AS d
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
		FROM chunk_domains AS d
		LEFT JOIN cert_agg AS ca ON ca.domain_id = d.domain_id
		LEFT JOIN policy_agg AS pa ON pa.domain_id = d.domain_id
		WHERE ca.cert_ids IS NOT NULL OR pa.policy_ids IS NOT NULL
		ON DUPLICATE KEY UPDATE
			cert_ids = VALUES(cert_ids),
			cert_ids_id = VALUES(cert_ids_id),
			policy_ids = VALUES(policy_ids),
			policy_ids_id = VALUES(policy_ids_id)
	");
	PREPARE stmt FROM @replace_sql;
	EXECUTE stmt;
	DEALLOCATE PREPARE stmt;

	SET @delete_payloads_sql = CONCAT("
		WITH RECURSIVE
		chunk_domains AS (
			SELECT domain_id
			FROM dirty PARTITION(p", partition_number, ") FORCE INDEX (dirty_coalesced)
			WHERE coalesced = FALSE
			ORDER BY domain_id
			LIMIT ", chunk_size, "
		),
		cert_closure AS (
			SELECT d.domain_id, c.cert_id, c.parent_id
			FROM chunk_domains AS d
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
			FROM chunk_domains AS d
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
		),
		final_result AS (
			SELECT
				d.domain_id,
				ca.cert_ids,
				pa.policy_ids
			FROM chunk_domains AS d
			LEFT JOIN cert_agg AS ca ON ca.domain_id = d.domain_id
			LEFT JOIN policy_agg AS pa ON pa.domain_id = d.domain_id
		)
		DELETE dp
		FROM domain_payloads PARTITION(p", partition_number, ") AS dp
		INNER JOIN final_result AS r
			ON dp.domain_id = r.domain_id
		WHERE r.cert_ids IS NULL AND r.policy_ids IS NULL
	");
	PREPARE stmt FROM @delete_payloads_sql;
	EXECUTE stmt;
	DEALLOCATE PREPARE stmt;

	SET @delete_domains_sql = CONCAT("
		WITH RECURSIVE
		chunk_domains AS (
			SELECT domain_id
			FROM dirty PARTITION(p", partition_number, ") FORCE INDEX (dirty_coalesced)
			WHERE coalesced = FALSE
			ORDER BY domain_id
			LIMIT ", chunk_size, "
		),
		cert_closure AS (
			SELECT d.domain_id, c.cert_id, c.parent_id
			FROM chunk_domains AS d
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
			FROM chunk_domains AS d
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
		),
		final_result AS (
			SELECT
				d.domain_id,
				ca.cert_ids,
				pa.policy_ids
			FROM chunk_domains AS d
			LEFT JOIN cert_agg AS ca ON ca.domain_id = d.domain_id
			LEFT JOIN policy_agg AS pa ON pa.domain_id = d.domain_id
		)
		DELETE dom
		FROM domains PARTITION(p", partition_number, ") AS dom
		INNER JOIN final_result AS r
			ON dom.domain_id = r.domain_id
		WHERE r.cert_ids IS NULL AND r.policy_ids IS NULL
	");
	PREPARE stmt FROM @delete_domains_sql;
	EXECUTE stmt;
	DEALLOCATE PREPARE stmt;

	SET @mark_coalesced_sql = CONCAT("
		UPDATE dirty PARTITION(p", partition_number, ") AS d
		INNER JOIN (
			SELECT domain_id
			FROM (
				SELECT domain_id
				FROM dirty PARTITION(p", partition_number, ") FORCE INDEX (dirty_coalesced)
				WHERE coalesced = FALSE
				ORDER BY domain_id
				LIMIT ", chunk_size, "
			) AS chunk_domains
		) AS t ON d.domain_id = t.domain_id
		SET d.coalesced = TRUE
	");
	PREPARE stmt FROM @mark_coalesced_sql;
	EXECUTE stmt;
	DEALLOCATE PREPARE stmt;

	COMMIT;
END
