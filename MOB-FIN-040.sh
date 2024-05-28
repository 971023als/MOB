#!/bin/bash

. function.sh

TMP1=$(mktemp)
> "$TMP1"

BAR

CODE [DBM-020] 사용자별 계정 분리 미흡

cat << EOF >> "$result"
[양호]: 사용자별 계정 분리가 올바르게 설정된 경우
[취약]: 사용자별 계정 분리가 충분하지 않은 경우
EOF

BAR

read -p "데이터베이스 관리자 사용자 이름을 입력하세요: " DB_USER
read -sp "데이터베이스 관리자 비밀번호를 입력하세요: " DB_PASS
echo

DB_CMD="mysql -u $DB_USER -p$DB_PASS -Bse"

USER_PRIVILEGES=$($DB_CMD "SELECT User, Host, Db, Select_priv, Insert_priv, Update_priv FROM mysql.db;")

echo "$USER_PRIVILEGES" | while read USER HOST DB SELECT_PRIV INSERT_PRIV UPDATE_PRIV; do
    if [[ "$SELECT_PRIV" == "Y" && "$INSERT_PRIV" == "Y" && "$UPDATE_PRIV" == "Y" ]]; then
        WARN "사용자 $USER@$HOST는 데이터베이스 $DB에 대해 과도한 권한을 가지고 있을 수 있습니다."
    else
        OK "사용자 $USER@$HOST는 데이터베이스 $DB에 적절한 권한을 가지고 있습니다."
    fi
done

cat "$result"

echo ; echo
