#!/bin/bash

# 함수 파일을 포함합니다.
. function.sh

# 임시 파일을 생성합니다.
TMP1=$(mktemp)
> "$TMP1"

# 구분선을 출력합니다.
BAR

# 검사 코드를 설정합니다.
CODE [DBM-024] 불필요한 WITH GRANT OPTION 옵션이 설정된 권한 존재

# 결과 파일에 내용을 추가합니다.
cat << EOF >> "$result"
[양호]: WITH GRANT OPTION 옵션이 불필요하게 설정되지 않은 경우
[경고]: WITH GRANT OPTION 옵션이 불필요하게 설정된 권한이 발견된 경우
EOF

# 구분선을 출력합니다.
BAR

# 데이터베이스 사용자 정보를 입력받습니다.
DB_USER="your_db_user"
DB_PASS="your_db_password"

# 데이터베이스에 연결하고 권한을 확인하는 명령어를 설정합니다.
DB_CMD="mysql -u $DB_USER -p$DB_PASS -Bse"

# WITH GRANT OPTION으로 부여된 권한을 확인합니다.
GRANT_OPTION_PRIVILEGES=$($DB_CMD "SELECT Grantee, Privilege_Type FROM information_schema.user_privileges WHERE IS_GRANTABLE = 'YES';")

if [ -z "$GRANT_OPTION_PRIVILEGES" ]; then
    OK "WITH GRANT OPTION 옵션이 불필요하게 설정된 권한이 없습니다."
else
    # 불필요한 권한을 순회하며 리스트합니다.
    echo "$GRANT_OPTION_PRIVILEGES" | while read -r grantee privilege; do
        WARN "불필요한 WITH GRANT OPTION 권한이 설정되었습니다: $grantee - $privilege"
    done
fi

# 결과 파일을 출력합니다.
cat "$result"

# 종료합니다.
echo ; echo
