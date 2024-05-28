#!/bin/bash

. function.sh

TMP1=$(SCRIPTNAME).log
> $TMP1

BAR

CODE [DBM-014] 취약한 운영체제 역할 인증 기능(OS_ROLES, REMOTE_OS_ROLES) 사용

cat << EOF >> $result
[양호]: OS_ROLES 및 REMOTE_OS_ROLES 기능이 비활성화되어 있는 경우
[취약]: OS_ROLES 또는 REMOTE_OS_ROLES 기능이 활성화되어 있는 경우
EOF

BAR

# Prompt for Oracle DB user information
read -p "Enter Oracle DB username: " ORACLE_USER
read -sp "Enter Oracle DB password: " ORACLE_PASS
echo

# SQL*Plus command execution
SQLPLUS_CMD="sqlplus -s /nolog"

# Check OS roles authentication settings
OS_ROLES=$(echo "conn $ORACLE_USER/$ORACLE_PASS
SET HEADING OFF;
SET FEEDBACK OFF;
SELECT value FROM v\$parameter WHERE name = 'os_roles';
EXIT;" | $SQLPLUS_CMD)

REMOTE_OS_ROLES=$(echo "conn $ORACLE_USER/$ORACLE_PASS
SET HEADING OFF;
SET FEEDBACK OFF;
SELECT value FROM v\$parameter WHERE name = 'remote_os_roles';
EXIT;" | $SQLPLUS_CMD)

if [[ "$OS_ROLES" == "FALSE" && "$REMOTE_OS_ROLES" == "FALSE" ]]; then
    OK "OS_ROLES 및 REMOTE_OS_ROLES 기능이 안전하게 비활성화되어 있습니다."
else
    WARN "OS_ROLES 또는 REMOTE_OS_ROLES 기능이 활성화되어 있어 취약할 수 있습니다."
fi

cat $result

echo ; echo
