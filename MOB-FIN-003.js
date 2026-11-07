#!/bin/bash

. function.sh

TMP1=${SCRIPTNAME}.log
> $TMP1

BAR

CODE [DBM-015] Public Role에 불필요한 권한 존재

cat << EOF >> $result
[양호]: Public Role에 불필요한 권한이 부여되지 않은 경우
[취약]: Public Role에 불필요한 권한이 부여된 경우
EOF

BAR

# Prompt for database user information
read -p "Enter database user name: " DB_USER
read -sp "Enter database password: " DB_PASS
echo

# Database command execution
DB_CMD="your_db_command_utility" # Replace with actual command utility like sqlplus, mysql etc.

echo "Checking for unnecessary privileges granted to PUBLIC role..."

# Check for unnecessary PUBLIC role privileges
# Replace with the actual query that lists privileges for the PUBLIC role in your database
# 비밀번호를 명령행 인자(-p"$DB_PASS")로 넘기면 프로세스 목록(ps)에 노출된다 (CWE-214).
# 환경변수로 전달하고 사용 후 unset 한다. (mysql은 MYSQL_PWD, psql은 PGPASSWORD 등 도구별 변수명 사용)
UNNECESSARY_PRIVILEGES=$(DB_TOOL_PASS="$DB_PASS" $DB_CMD -u "$DB_USER" -e "CHECK QUERY TO LIST PRIVILEGES FOR PUBLIC ROLE;")
unset DB_PASS DB_TOOL_PASS

# Check if unnecessary privileges are granted
if [ -z "$UNNECESSARY_PRIVILEGES" ]; then
    OK "No unnecessary privileges granted to PUBLIC role."
else
    WARN "The following unnecessary privileges are granted to PUBLIC role: $UNNECESSARY_PRIVILEGES"
fi

cat $result

echo ; echo
