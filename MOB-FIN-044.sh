#!/bin/bash

. function.sh

TMP1=$(mktemp)
> "$TMP1"

BAR

CODE [DBM-022] 설정 파일 및 중요정보가 포함된 파일의 접근 권한 설정 미흡

cat << EOF >> "$result"
[양호]: 설정 파일 및 중요 정보가 포함된 파일의 접근 권한이 적절하게 설정된 경우
[취약]: 설정 파일 및 중요 정보가 포함된 파일의 접근 권한이 미흡한 경우
EOF

BAR

# 설정 파일 및 중요 정보 파일 목록
CONFIG_FILES="/path/to/configfile1 /path/to/configfile2"

# 권한 검사
for FILE in $CONFIG_FILES; do
    if [ ! -f "$FILE" ]; then
        WARN "중요 설정 파일이 존재하지 않습니다: $FILE"
        continue
    fi

    PERMISSIONS=$(stat -c "%a" "$FILE")
    if [ "$PERMISSIONS" -ne "600" ]; then
        WARN "적절하지 않은 접근 권한이 설정된 중요 파일: $FILE (현재 권한: $PERMISSIONS)"
    else
        OK "적절한 접근 권한이 설정된 중요 파일: $FILE"
    fi
done

cat "$result"

echo ; echo
