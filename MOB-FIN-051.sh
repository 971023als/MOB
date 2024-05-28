#!/bin/bash

. function.sh

TMP1=$(SCRIPTNAME).log
> $TMP1

BAR

CODE [SRV-027] 서비스 접근 IP 및 포트 제한 미비

cat << EOF >> $result
[양호]: 서비스에 대한 IP 및 포트 접근 제한이 적절하게 설정된 경우
[취약]: 서비스에 대한 IP 및 포트 접근 제한이 설정되지 않은 경우
EOF

BAR

# 예시로, iptables 또는 firewalld를 사용하여 특정 서비스에 대한 접근 제한을 확인할 수 있습니다.
# 여기서는 SSH(포트 22)에 대한 접근 제한을 확인합니다.

if iptables -L | grep -q "dport 22"; then
    OK "SSH 서비스에 대한 포트 접근 제한이 설정되어 있습니다."
else
    WARN "SSH 서비스에 대한 포트 접근 제한이 설정되어 있지 않습니다."
fi

cat $result

echo ; echo
