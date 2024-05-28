#!/bin/bash

# 함수 라이브러리 포함
. function.sh

TMP1=$(mktemp)
> "$TMP1"

BAR

CODE [DBM-021] 업무상 불필요한 ODBC/OLE-DB 데이터 소스 및 드라이버 존재

cat << EOF >> "$result"
[양호]: 모든 ODBC/OLE-DB 데이터 소스 및 드라이버가 업무에 필요한 경우
[취약]: 업무상 필요하지 않은 ODBC/OLE-DB 데이터 소스 또는 드라이버가 존재하는 경우
EOF

BAR

# ODBC 데이터 소스 목록 확인
ODBC_SOURCES=$(odbcinst -q -s)
# OLE-DB 드라이버 목록 확인 (Windows 환경의 예시 명령어)
OLEDB_DRIVERS=$(oleview | grep 'OLE DB')

# 확인된 데이터 소스 및 드라이버를 업무 필요성에 따라 검토
# 여기에 실제 업무상 필요한 데이터 소스 및 드라이버 목록을 비교하는 로직을 구현합니다.

# 예시 로직
NECESSARY_SOURCES="known_necessary_source_list"
for SOURCE in $ODBC_SOURCES; do
    if ! grep -q "$SOURCE" <<< "$NECESSARY_SOURCES"; then
        WARN "업무상 불필요한 ODBC 데이터 소스가 존재합니다: $SOURCE"
    fi
done

for DRIVER in $OLEDB_DRIVERS; do
    if ! grep -q "$DRIVER" <<< "$NECESSARY_SOURCES"; then
        WARN "업무상 불필요한 OLE-DB 드라이버가 존재합니다: $DRIVER"
    fi
done

# 결과 파일 출력
cat "$result"

# 종료 줄바꿈
echo ; echo
