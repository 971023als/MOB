#!/bin/bash

# 함수 라이브러리 포함
. function.sh

# 임시 파일 생성
TMP1=$(mktemp)
> "$TMP1"

# 구분선 출력
BAR

# 검사 코드
CODE [DBM-019] 비밀번호 재사용 방지 설정 미흡

# 결과 파일에 내용 추가
cat << EOF >> "$result"
[양호]: 비밀번호 재사용 방지가 올바르게 설정된 경우
[취약]: 비밀번호 재사용 방지가 제대로 설정되지 않은 경우
EOF

# 구분선 출력
BAR

# 데이터베이스 사용자 정보 입력받기
read -p "데이터베이스 사용자 이름을 입력하세요: " DB_USER
read -sp "데이터베이스 비밀번호를 입력하세요: " DB_PASS
echo

# 데이터베이스 명령 실행 변수 설정
DB_CMD="데이터베이스_명령어_경로" # 실제 데이터베이스 명령어로 변경해야 함

# 비밀번호 재사용 방지 설정 확인
PASSWORD_REUSE_POLICY=$($DB_CMD -u $DB_USER -p$DB_PASS -e "비밀번호 재사용 관련 설정 확인 쿼리")

# 비밀번호 재사용 방지 설정 로직 검사
if [ -z "$PASSWORD_REUSE_POLICY" ]; then
    WARN "비밀번호 재사용 방지 설정이 구성되어 있지 않습니다."
else
    # 재사용 방지가 효과적으로 설정되었는지 확인
    PASSWORD_HISTORY=$(echo $PASSWORD_REUSE_POLICY | awk '{ print $2 }')
    if [ "$PASSWORD_HISTORY" -ge "원하는_히스토리_숫자" ]; then
        OK "비밀번호 재사용 방지가 $PASSWORD_HISTORY의 기록으로 올바르게 설정되어 있습니다."
    else
        WARN "비밀번호 재사용 방지 설정은 있으나 $PASSWORD_HISTORY 기록으로는 충분하지 않습니다."
    fi
fi

# 결과 파일 출력
cat "$result"

# 종료 줄바꿈
echo ; echo
