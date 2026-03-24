# RAID0 Creation in Articuno

Optimal parameters for the RAID and filesystem appear to be critical.
References:
- https://erikugel.wordpress.com/tag/raid0/
- https://planet.mysql.com/entry/?id=29095

Chosen parameters for RAID:
- Stripe unit: 4Kb
- RAID0 stripe size (chunk): 4x4Kb = 64Kb

```bash
# Create RAID0. If a RAID exists already, follow steps to deactivate and erase superblocks.
sudo mdadm --create /dev/md0  --level=0 --chunk=64 --raid-devices=4 /dev/nvme[0123]n1
# Should have output:
#mdadm: Defaulting to version 1.2 metadata
#mdadm: array /dev/md0 started.

# Check RAID status:
cat /proc/mdstat
# Should have output:
#Personalities : [raid0] [linear] [multipath] [raid1] [raid6] [raid5] [raid4] [raid10]
#md0 : active raid0 nvme3n1[3] nvme2n1[2] nvme1n1[1] nvme0n1[0]
#      7813529856 blocks super 1.2 64k chunks
#
#unused devices: <none>

# Save raid configuration:
sudo mdadm --detail --scan | sudo tee -a /etc/mdadm/mdadm.conf

# Update initram to make raid available at early boot:
sudo update-initramfs -u
```


## Filesystem

Option between ext4 and XFS. Since (from benchmarks for MySQL) XFS is only just a bit faster, choose ext4.

```bash
# Filesystem parameters:
sudo mkfs.ext4 -b 4096 -E stride=16,stripe-width=64 /dev/md0

# Tune journal for fastest write:
sudo tune2fs -O has_journal -o journal_data_writeback /dev/md0

# Turn on directory indexing:
sudo tune2fs -O dir_index /dev/md0
# And optimize directories:
sudo e2fsck -D /dev/md0
```

Add the following entry to `fstab`:
```
/dev/md0         /                ext4        noatime,nodiratime,data=writeback,stripe=64,barrier=0,errors=remount-ro      1   1
```

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

#### USB performance
The raw reading speed of the USB disk is measured at 201MB/s by `dd`:

```shell
$ dd if=/dev/random of=test-data.dat bs=1024 count=10M # 10Gb of data
10485760+0 records in
10485760+0 records out
10737418240 bytes (11 GB, 10 GiB) copied, 42.8253 s, 251 MB/s

# Drop caches
$ time { echo 3 | sudo tee /proc/sys/vm/drop_caches; }
3

real	0m27.080s
user	0m0.009s
sys	0m0.016s

$ sudo dd if=test-data.dat of=/dev/null bs=1024
10485760+0 records in
10485760+0 records out
10737418240 bytes (11 GB, 10 GiB) copied, 53.4006 s, 201 MB/s
```

#### RAID0 performance
Clean cache, dentries and inodes:
```
echo 3 | sudo tee /proc/sys/vm/drop_caches
```

Measurement
- Read:  2.2 GB/s
```bash
$ dd of=/dev/null if=test bs=1M
10000+0 records in
10000+0 records out
10485760000 bytes (10 GB, 9.8 GiB) copied, 4.74762 s, 2.2 GB/s
```

- Write: ~~134 MB/s~~ 1.11 GB/s

```diff
+ # Left here for reference. Below is a more accurate measurement.
- $ dd if=/dev/zero of=test bs=1M count=10000 oflag=dsync
- 10000+0 records in
- 10000+0 records out
- 10485760000 bytes (10 GB, 9.8 GiB) copied, 78.5443 s, 134 MB/s
```
```bash
$ sync; time { dd if=/dev/zero of=test bs=1M count=10000 && sync; }
10000+0 records in
10000+0 records out
10485760000 bytes (10 GB, 9.8 GiB) copied, 7.39969 s, 1.4 GB/s

real	0m8.989s
user	0m0.001s
sys	0m8.967s
```

- With `hdparm`: read is ~ 2.2 GB/s (no cache)
```bash
$ sudo hdparm -tT /dev/md0

/dev/md0:
 Timing cached reads:   21778 MB in  2.00 seconds = 10901.08 MB/sec
 Timing buffered disk reads: 6588 MB in  3.00 seconds = 2195.60 MB/sec
```

## Ingest

### xenon2025h1
Path: `/mnt/data/certificatestore/https:__ct.googleapis.com_logs_eu1_xenon2025h1`.

Contains:
- 480 bundle files
- 83031345 unique certificates:
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

### Test Set

Create with:
```bash
mkdir -p /mnt/data/certificatestore/test/bundled
FILES=$(ls /mnt/data/certificatestore/https\:__ct.googleapis.com_logs_eu1_xenon2025h1/bundled/  | sort -n | head -n 10)
echo cp $FILES /mnt/data/certificatestore/test/bundled
```

Path: `/mnt/data/certificatestore/test`
Contains:
- 10 bundle files
- 1000865 unique certificates


#### MyISAM

Ingestion (total)
- With overwrite using 32 DB workers: 5m 26s
- With keep using 32 DB workers: 5m 10s

Note that although MyISAM locks the table per operation, reenabling keys (and maybe coalescing)
could be done in parallel for different tables. Coalescing is bounded by CPU usage (1 core).

The SMT update seems to be bounded by CPU as well.

#### InnoDB

Ingestion (total)
- InnoDB (keep): 4m 8s
    - Note that "keep" triggers an error with many DB workers. Using 2 for this.
- InnoDB (overwrite):
    - 6m 2s (2 DB workers)
    - 5m 21s (32 DB workers)

Note that reenabling keys and coalescing run in a single thread.
CPU bounds these steps, particularly coalescing, where there is not a lot of IO.

The SMT update seems to be bounded by CPU as well.


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
