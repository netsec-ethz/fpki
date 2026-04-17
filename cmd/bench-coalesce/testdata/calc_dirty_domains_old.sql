CREATE PROCEDURE calc_dirty_domains(IN partition_number INT)
BEGIN
	SET group_concat_max_len = 1073741824;

	SET @sql = CONCAT("
	REPLACE INTO domain_payloads(domain_id, cert_ids, cert_ids_id, policy_ids, policy_ids_id)
	SELECT domain_id, cert_ids, UNHEX(SHA2(cert_ids, 256)) AS cert_ids_id, policy_ids, UNHEX(SHA2(policy_ids, 256)) AS policy_ids_id FROM
	(

	SELECT A.domain_id,GROUP_CONCAT(cert_id ORDER BY cert_id SEPARATOR '') AS cert_ids,GROUP_CONCAT(policy_id ORDER BY policy_id SEPARATOR '') AS policy_ids FROM
		(
			WITH RECURSIVE cte AS (
				SELECT dirty.domain_id, certs.cert_id, parent_id
				FROM certs
				INNER JOIN domain_certs ON certs.cert_id = domain_certs.cert_id
				INNER JOIN dirty PARTITION(p", partition_number,") ON domain_certs.domain_id = dirty.domain_id
				UNION ALL
				SELECT cte.domain_id, certs.cert_id, certs.parent_id
				FROM certs
				JOIN cte ON certs.cert_id = cte.parent_id
			)
			SELECT DISTINCT domain_id, cert_id FROM cte
		) AS A
	LEFT OUTER JOIN
		(
			WITH RECURSIVE cte AS (
				SELECT dirty.domain_id, policies.policy_id, parent_id
				FROM policies
				INNER JOIN domain_policies ON policies.policy_id = domain_policies.policy_id
				INNER JOIN dirty PARTITION(p", partition_number, ") ON domain_policies.domain_id = dirty.domain_id
				UNION ALL
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
				SELECT dirty.domain_id, certs.cert_id, parent_id
				FROM certs
				INNER JOIN domain_certs ON certs.cert_id = domain_certs.cert_id
				INNER JOIN dirty PARTITION(p", partition_number, ") ON domain_certs.domain_id = dirty.domain_id
				UNION ALL
				SELECT cte.domain_id, certs.cert_id, certs.parent_id
				FROM certs
				JOIN cte ON certs.cert_id = cte.parent_id
			)
			SELECT DISTINCT domain_id, cert_id FROM cte
		) AS A
	RIGHT OUTER JOIN
		(
			WITH RECURSIVE cte AS (
				SELECT dirty.domain_id, policies.policy_id, parent_id
				FROM policies
				INNER JOIN domain_policies ON policies.policy_id = domain_policies.policy_id
				INNER JOIN dirty PARTITION(p", partition_number, ") ON domain_policies.domain_id = dirty.domain_id
				UNION ALL
				SELECT cte.domain_id, policies.policy_id, policies.parent_id
				FROM policies
				JOIN cte ON policies.policy_id = cte.parent_id
			)
			SELECT DISTINCT domain_id, policy_id FROM cte
		) AS B
	ON A.domain_id = B.domain_id
	GROUP BY domain_id

	) AS hasher_query;"
	);
	PREPARE stmt FROM @sql;
	EXECUTE stmt;
	DEALLOCATE PREPARE stmt;
END
