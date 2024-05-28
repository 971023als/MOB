#!/bin/bash

. function.sh

TMP1=$(SCRIPTNAME).log
> $TMP1

BAR

CODE [SRV-026] root 계정 원격 접속 제한 미비

cat << EOF >> $result
[양호]: SSH를 통한 root 계정의 원격 접속이 제한된 경우
[취약]: SSH를 통한 root 계정의 원격 접속이 제한되지 않은 경우
EOF

BAR

# SSH 설정 파일에서 root 로그인을 허용하는 설정을 확인합니다.
SSH_CONFIG_FILE="/etc/ssh/sshd_config"

if grep -q "^PermitRootLogin no" "$SSH_CONFIG_FILE"; then
    OK "SSH를 통한 root 계정의 원격 접속이 제한됩니다."
else
    WARN "SSH를 통한 root 계정의 원격 접속이 허용됩니다."
fi

cat $result

echo ; echo
