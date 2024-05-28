#!/bin/bash

. function.sh

TMP1=$(SCRIPTNAME).log
> $TMP1

BAR

CODE [SRV-034] 불필요한 서비스 활성화

cat << EOF >> $result
[양호]: 불필요한 서비스가 비활성화된 경우
[취약]: 불필요한 서비스가 활성화된 경우
EOF

BAR

# 불필요하거나 보안에 영향을 줄 수 있는 서비스 목록
UNNECESSARY_SERVICES=("telnet" "ftp" "nfs-server" "rpcbind" "smb" "snmpd")

for service in "${UNNECESSARY_SERVICES[@]}"; do
  if systemctl is-active --quiet $service; then
    WARN "$service 서비스가 활성화되어 있습니다."
  else
    OK "$service 서비스가 비활성화되어 있습니다."
  fi
done

cat $result

echo ; echo
