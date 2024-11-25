#!/bin/bash

. function.sh

TMP1=$(SCRIPTNAME).log
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
UNNECESSARY_PRIVILEGES=$($DB_CMD -u "$DB_USER" -p"$DB_PASS" -e "CHECK QUERY TO LIST PRIVILEGES FOR PUBLIC ROLE;")

# Check if unnecessary privileges are granted
if [ -z "$UNNECESSARY_PRIVILEGES" ]; then
    OK "No unnecessary privileges granted to PUBLIC role."
else
    WARN "The following unnecessary privileges are granted to PUBLIC role: $UNNECESSARY_PRIVILEGES"
fi

cat $result

echo ; echo
