CREATE PROCEDURE calc_dirty_domains(IN partition_number INT)
BEGIN
	SET group_concat_max_len = 1073741824;

	SET @delete_payloads_sql = CONCAT("
		DELETE dp
		FROM domain_payloads PARTITION(p", partition_number, ") AS dp
		INNER JOIN dirty PARTITION(p", partition_number, ") AS d
			ON dp.domain_id = d.domain_id
		WHERE NOT EXISTS (
			SELECT 1
			FROM domain_certs AS dc
			WHERE dc.domain_id = dp.domain_id
		)
		AND NOT EXISTS (
			SELECT 1
			FROM domain_policies AS pol
			WHERE pol.domain_id = dp.domain_id
		)
	");
	PREPARE stmt FROM @delete_payloads_sql;
	EXECUTE stmt;
	DEALLOCATE PREPARE stmt;

	SET @delete_domains_sql = CONCAT("
		DELETE dom
		FROM domains PARTITION(p", partition_number, ") AS dom
		INNER JOIN dirty PARTITION(p", partition_number, ") AS d
			ON dom.domain_id = d.domain_id
		WHERE NOT EXISTS (
			SELECT 1
			FROM domain_certs AS dc
			WHERE dc.domain_id = dom.domain_id
		)
		AND NOT EXISTS (
			SELECT 1
			FROM domain_policies AS dp
			WHERE dp.domain_id = dom.domain_id
		)
	");
	PREPARE stmt FROM @delete_domains_sql;
	EXECUTE stmt;
	DEALLOCATE PREPARE stmt;

	SET @insert_sql = CONCAT("
		REPLACE INTO domain_payloads(domain_id, cert_ids, cert_ids_id, policy_ids, policy_ids_id)
		WITH RECURSIVE
		cert_closure AS (
			SELECT d.domain_id, c.cert_id, c.parent_id
			FROM dirty PARTITION(p", partition_number, ") AS d
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
			FROM dirty PARTITION(p", partition_number, ") AS d
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
		FROM dirty PARTITION(p", partition_number, ") AS d
		LEFT JOIN cert_agg AS ca ON ca.domain_id = d.domain_id
		LEFT JOIN policy_agg AS pa ON pa.domain_id = d.domain_id
		WHERE ca.cert_ids IS NOT NULL OR pa.policy_ids IS NOT NULL
	");
	PREPARE stmt FROM @insert_sql;
	EXECUTE stmt;
	DEALLOCATE PREPARE stmt;
END
