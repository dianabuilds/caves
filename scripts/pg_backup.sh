#!/bin/bash
set -euo pipefail

: "${DATABASE_URL?Need DATABASE_URL}"
: "${S3_BUCKET?Need S3_BUCKET}"

DATE=$(date +%Y%m%d%H%M%S)
FILE="backup_${DATE}.sql.gz"

pg_dump "$DATABASE_URL" | gzip > "$FILE"
aws s3 cp "$FILE" "s3://$S3_BUCKET/$FILE"
rm "$FILE"

aws s3 ls "s3://$S3_BUCKET/" | while read -r line; do
  created=$(echo $line | awk '{print $1" "$2}')
  fname=$(echo $line | awk '{print $4}')
  if [[ $fname == backup_* ]]; then
    created_ts=$(date -d "$created" +%s)
    older_than=$(date -d '30 days ago' +%s)
    if (( created_ts < older_than )); then
      aws s3 rm "s3://$S3_BUCKET/$fname"
    fi
  fi
done
