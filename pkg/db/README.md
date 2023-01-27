
# Legacy, notes from Yongzhe
For functions which retrieves one key-value pair, sql.ErrNoRows will be thrown if no rows is founded.
For functions which retrieves a list of key-value pairs, sql.ErrNoRows will be omitted. So please check the length of the output to decide if the fetching is incomplete. 

# New notes

# Design

The DB supports the map server in two aspects:
1. Stores the certificates and their trust chains
2. Stores the Sparse Merkle Tree structure on disk

We need very efficient requests based on the domain name.
The update process has to simply retrieve the new certificates and their trust chains,
add them to the DB, write down those updated domains, and process the SMT for those
domains only.


## Tables
For performance reasons, no foreign keys exist in any table.

- `certs` table
    1. `id`: PK, this is the SHA256 of the certificate.
    2. `payload`: BLOB, this is the certificate, serialized.
    3. `parent`: this is the parent certificate, in the trust chain, or `NULL` if root.
- `domains` table. This table is updated in DB from the `certs` table
    1. `cert_id`: PK, SHA256 of the certificate
    2. `domain_id`: PK, SHA256 of the domain
    3. `domain`: index, text, the name of the domain
    4. `payload_id`: BIGINT, points to the serialized certificate collection,
    according to the rules.
- `domain_payloads` table. Holds the collection of certificates for each domain.
    This comes from all the certificates that have their `certs.domain` equal
    to this `domains.domain`, serialized following certain rules.
    1. `id`: BIGINT
    2. `payload`: BLOB
    4. `payload_hash`: SHA256 of the serialized certificate collection for the domain.
- `dirty` table
    1. `domain_id`: PK, SHA256 of each of the modified domains.

SMT tables:
- `tree` table, remains the same as before
    1. `id`: PK, auto increment.
    2. `key32`: index, whatever the SMT library uses as key, 32 bytes.
    3. `value`: whatever the SMT library uses as value.
- `root` table. Should contain zero or one elements.
    1. `key32`: PK, 32 bytes, SHA256 of the root of the SMT.

The `dirty` table should always be non-empty when the SMT update process starts,
as it contains the domains that have been altered, and those that will be
sent to the SMT to update.



## Update Process
We describe the update process with the following steps:
1. Obtain the data.
2. Create (`upsert` or similar) a new record per new certificate C and domain D.
3. Write the modified domains into a table `dirty` (formerly known as the `updates` table).
4. In DB and via a stored procedure,
serialize the certificate collection (following certain rules) and write it, plus its SHA256,
to the table.
5. Wait until all batches have finished.
6. Update the SMT with the material from (4), and using the domains in `dirty`.
7. Store the `tree` table in DB.
8. Truncate the `dirty` table.
