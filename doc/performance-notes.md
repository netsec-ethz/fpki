# Performance of Mapserver in our systems (Articuno)

Two modes of operation
1. Reading locally from USB, mapserver as a service
2. Reading locally from RAID0, mapserver command line

## From USB, Mapserver as a Service

At the moment in Articuno, we ingest 200,000 certificates every 4 minutes.

## From RAID0, command line

We need to ingest all log server, like:
/mnt/external/ct-log-download/certificates/https:__ct.googleapis.com_logs_eu1_xenon2024/bundled


### Numbers

It takes 5m28s to copy 59G from USB to RAID0. That yields a speed of 184 Mb/s.

Current USB size:
```
611M	https:__ct.googleapis.com_logs_eu1_xenon2025h2
611M	https:__ct.googleapis.com_logs_us1_argon2025h2
59G	    https:__ct.googleapis.com_logs_eu1_xenon2025h1
72G	    https:__ct.googleapis.com_logs_us1_argon2025h1
1.5T	https:__ct.googleapis.com_logs_us1_argon2024
1.8T	https:__ct.googleapis.com_logs_eu1_xenon2024
```

#### xenon2025h1
Path: `/mnt/data/certificatestore/https:__ct.googleapis.com_logs_eu1_xenon2025h1`.

Contains 83031345 unique certificates:
```
select count(*) from dirty;
+----------+
| count(*) |
+----------+
| 83031345 |
+----------+
1 row in set (0.00 sec)
```

Ingestion of certificates and coalescing:
343m51s

Coalescing alone:
178m30s

SMT Update fails

|               |      |
----------------|-------
| Certificates  | 166m |
| Coalescing    | 179m |
| SMT update    | ??   |
------------------------

### TODO
1. Disable Mapserver systemd service
<!-- 1. Reset DB with `./create_schema.sh` -->
2. Per CT log server as `SERVER`, starting with the smallest one:
    1. Copy from `/mnt/external/ct-log-download/certificates/SERVER/bundled/` to `/mnt/data/certificatestore`
    2. Manually run `ingest` for that directory
    3. Check free space on disk

Script to copy USB to RAID0:
```bash
#!/bin/bash

set -e

# https:__ct.googleapis.com_logs_eu1_xenon2025h2  and
# https:__ct.googleapis.com_logs_us1_argon2025h2
# have no files inside "bundled". Skipping.
SERVERS="https:__ct.googleapis.com_logs_eu1_xenon2025h1
https:__ct.googleapis.com_logs_us1_argon2025h1
https:__ct.googleapis.com_logs_us1_argon2024
https:__ct.googleapis.com_logs_eu1_xenon2024"

# Use here-string to feed the SERVERS variable to while loop
while IFS= read -r server; do
    echo "`date` copying $server"
    SRC="/mnt/external/ct-log-download/certificates/${server}/bundled"
    DST="/certificatestore/${server}"
    mkdir -p "$DST"
    time cp -a "$SRC" "${DST}/"
done <<< "$SERVERS"
```
