#!/bin/bash

. function.sh

# Temporary log file
TMP1=$(mktemp)
> "$TMP1"

# Header for the check
BAR
CODE [DBM-025] 사용중인 데이터베이스가 서비스 지원 종료(EoS) 버전인지 확인

cat << EOF >> "$result"
[양호]: 현재 사용 중인 데이터베이스 버전이 서비스 지원 기간 내에 있는 경우
[취약]: 현재 사용 중인 데이터베이스 버전이 서비스 지원 종료(EoS)에 도달한 경우
EOF

# Header for the end of the check
BAR

# Insert your database command to check the version
DB_VERSION=$(your_command_to_check_db_version)

# You should have a list of EoS versions to compare against
# For the sake of this example, let's assume you have them in an array
EOS_VERSIONS=('version1' 'version2' 'version3')

for eos_version in "${EOS_VERSIONS[@]}"; do
    if [[ "$DB_VERSION" == "$eos_version" ]]; then
        WARN "현재 사용 중인 데이터베이스 버전($DB_VERSION)은 서비스 지원 종료(EoS)에 도달했습니다."
        break
    fi
done

# If the loop completes without finding a match, then the version is not EoS
if [[ $eos_version != "$DB_VERSION" ]]; then
    OK "현재 사용 중인 데이터베이스 버전($DB_VERSION)은 서비스 지원 기간 내에 있습니다."
fi

# Display the results
cat "$result"

# End of script
echo ; echo
