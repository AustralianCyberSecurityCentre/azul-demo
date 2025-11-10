#!/bin/bash
set -x
set -e

# set password hash in internal_users.yml for admin and dashboards user
chmod +x /usr/share/opensearch/plugins/opensearch-security/tools/hash.sh

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

PW_ADMIN_H=$(/usr/share/opensearch/plugins/opensearch-security/tools/hash.sh -p $PW_ADMIN | tail -n 1)
PW_DASH_H=$(/usr/share/opensearch/plugins/opensearch-security/tools/hash.sh -p $PW_DASH | tail -n 1)
PW_AZWRITER_H=$(/usr/share/opensearch/plugins/opensearch-security/tools/hash.sh -p $PW_AZULW | tail -n 1)

# fix encoding for sed
PW_ADMIN_H=$(printf '%q\n' $PW_ADMIN_H | awk -F'/' -v OFS="\\\\/" '$1=$1' )
PW_DASH_H=$(printf '%q\n' $PW_DASH_H | awk -F'/' -v OFS="\\\\/" '$1=$1' )
PW_AZWRITER_H=$(printf '%q\n' $PW_AZWRITER_H | awk -F'/' -v OFS="\\\\/" '$1=$1' )

REWRITE=/usr/share/opensearch/config/opensearch-security/internal_users.yml
cp $REWRITE.tpl $REWRITE
sed -i "s/ADMIN_PLACEHOLDER/$PW_ADMIN_H/g" $REWRITE
sed -i "s/KS_PLACEHOLDER/$PW_DASH_H/g" $REWRITE
sed -i "s/AZW_PLACEHOLDER/$PW_AZWRITER_H/g" $REWRITE

# initialise security plugin (erases all previous roles)
chmod +x /usr/share/opensearch/plugins/opensearch-security/tools/securityadmin.sh

/usr/share/opensearch/plugins/opensearch-security/tools/securityadmin.sh \
    -f /usr/share/opensearch/config/opensearch-security/config.yml \
    -icl -nhnv  \
    -cacert /usr/share/opensearch/config/root-ca.pem \
    -cert /usr/share/opensearch/config/kirk.pem \
    -key /usr/share/opensearch/config/kirk-key.pem

/usr/share/opensearch/plugins/opensearch-security/tools/securityadmin.sh \
    -f /usr/share/opensearch/config/opensearch-security/internal_users.yml \
    -icl -nhnv  \
    -cacert /usr/share/opensearch/config/root-ca.pem \
    -cert /usr/share/opensearch/config/kirk.pem \
    -key /usr/share/opensearch/config/kirk-key.pem

# just in case
sleep 1

# create roles and users in opendistro for azul
ENDPOINT=${ENDPOINT:="https://localhost:9200"}
CERT=${CERT:="$SCRIPT_DIR/../config/kirk.pem"}
KEY=${KEY:="$SCRIPT_DIR/../config/kirk-key.pem"}
CACERT=${CACERT:="$SCRIPT_DIR/../config/root-ca.pem"}


put () {
    echo $2
    curl \
        --cert $CERT \
        --key $KEY \
        --cacert $CACERT \
        --insecure \
        --data-binary "@$SCRIPT_DIR/$2" \
        -XPUT \
        -H "Content-Type: application/json" \
        $ENDPOINT/_opendistro/_security/api/$1/$3
    echo
    echo
}

put roles role_admin.json azul_admin
put roles role_official.json s-official

put rolesmapping role_map_admin.json azul_admin
put rolesmapping role_map_all_access.json all_access
put rolesmapping role_map_official.json s-official

put tenants tenant.json azul

put internalusers user_write.json azul_writer
put internalusers user_admin.json azul_admin

echo "*************************** Opensearch inatialized ***************************"