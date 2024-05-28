#!/bin/bash

. function.sh

TMP1=$(mktemp)
> "$TMP1"

BAR

CODE [DBM-017] 업무상 불필요한 시스템 테이블 접근 권한 존재

cat << EOF >> "$result"
[양호]: 업무상 불필요한 시스템 테이블 접근 권한이 없는 경우
[취약]: 업무상 불필요한 시스템 테이블 접근 권한이 존재하는 경우
EOF

BAR

# 데이터베이스 사용자 정보 입력받기
read -p "Enter the database username: " DB_USER
read -sp "Enter the database password: " DB_PASS
echo

# MySQL 명령 실행
MYSQL_CMD="mysql -u $DB_USER -p$DB_PASS -Bse"

# 시스템 테이블 권한 확인
SYSTEM_TABLE_PRIVILEGES=$($MYSQL_CMD "SELECT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE FROM information_schema.SCHEMA_PRIVILEGES WHERE TABLE_SCHEMA = 'mysql' OR TABLE_SCHEMA = 'information_schema' OR TABLE_SCHEMA = 'performance_schema';")

if [ -z "$SYSTEM_TABLE_PRIVILEGES" ]; then
    OK "업무상 불필요한 시스템 테이블 접근 권한이 존재하지 않습니다."
else
    WARN "다음 사용자에게 업무상 불필요한 시스템 테이블 접근 권한이 부여되었습니다:"
    echo "$SYSTEM_TABLE_PRIVILEGES"
fi

cat "$result"

echo ; echo
