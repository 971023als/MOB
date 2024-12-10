#!/bin/bash

. function.sh

TMP1=$(SCRIPTNAME).log
> $TMP1

BAR

CODE [DBM-011] 감사 로그 수집 및 백업 미흡

cat << EOF >> $result
[양호]: 감사 로그가 정기적으로 수집 및 백업되고 있는 경우
[취약]: 감사 로그 수집 및 백업 정책이 미흡한 경우
EOF

BAR

# Audit log directory
audit_log_dir="/var/log/audit"

# Check if audit logs are being collected
if [ "$(find $audit_log_dir -type f -name '*.log' | wc -l)" -gt 0 ]; then
    OK "감사 로그가 정기적으로 수집되고 있습니다."
else
    WARN "감사 로그가 수집되지 않고 있습니다."
fi

# Backup directory
backup_dir="/var/backup/audit"

# Check for recent backup files
if [ "$(find $backup_dir -type f -name '*.bak' -mtime -30 | wc -l)" -gt 0 ]; then
    OK "감사 로그가 최근 30일 이내에 백업되었습니다."
else
    WARN "감사 로그 백업이 30일 이상 되지 않았습니다."
fi

cat $result

echo ; echo
