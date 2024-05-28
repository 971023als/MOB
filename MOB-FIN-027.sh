#!/bin/bash

. function.sh

TMP1=`SCRIPTNAME`.log
> $TMP1

BAR

CODE [DBM-012] Listener Control Utility(lsnrctl) 보안 설정 미흡

cat << EOF >> $result
[양호]: Listener Control Utility 보안 설정이 적절히 적용된 경우
[취약]: Listener Control Utility 보안 설정이 미흡한 경우
EOF

BAR

# Listener configuration file
listener_ora="/path/to/your/listener.ora"

# Check if the listener.ora file exists
if [ -f "$listener_ora" ]; then
    # Check for security settings like ADMIN_RESTRICTIONS_LISTENER=ON
    if grep -q "ADMIN_RESTRICTIONS_LISTENER=ON" "$listener_ora"; then
        OK "Listener Control Utility 보안 설정이 적절히 적용되었습니다."
    else
        WARN "Listener Control Utility에 ADMIN_RESTRICTIONS_LISTENER 설정이 적용되지 않았습니다."
    fi
else
    WARN "Listener configuration file이 존재하지 않습니다."
fi

cat $result

echo ; echo
