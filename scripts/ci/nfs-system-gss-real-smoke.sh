#!/usr/bin/env bash
set -euo pipefail

REALM="NAOS.TEST"
SERVICE_PRINCIPAL="nfs/localhost@${REALM}"
CLIENT_PRINCIPAL="alice@${REALM}"
KDC_PORT="${NAOS_TEST_KDC_PORT:-61088}"
WORK_ROOT="${RUNNER_TEMP:-/tmp}/naos-krb5-$$"
KRB5_CONF="${WORK_ROOT}/krb5.conf"
KDC_CONF="${WORK_ROOT}/kdc.conf"
SERVICE_KEYTAB="${WORK_ROOT}/service.keytab"
CLIENT_KEYTAB="${WORK_ROOT}/client.keytab"
CLIENT_CCACHE="${WORK_ROOT}/client.ccache"
KDC_LOG="${WORK_ROOT}/krb5kdc.log"
KDC_PID=""

cleanup() {
    if [[ -n "${KDC_PID}" ]] && kill -0 "${KDC_PID}" 2>/dev/null; then
        kill "${KDC_PID}" 2>/dev/null || true
        wait "${KDC_PID}" 2>/dev/null || true
    fi
    rm -rf "${WORK_ROOT}"
}
trap cleanup EXIT

mkdir -p "${WORK_ROOT}"

cat >"${KRB5_CONF}" <<EOF
[libdefaults]
    default_realm = ${REALM}
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    dns_canonicalize_hostname = false
    udp_preference_limit = 1

[realms]
    ${REALM} = {
        kdc = 127.0.0.1:${KDC_PORT}
    }
EOF

cat >"${KDC_CONF}" <<EOF
[kdcdefaults]
    kdc_ports = ${KDC_PORT}
    kdc_tcp_ports = ${KDC_PORT}

[realms]
    ${REALM} = {
        database_name = ${WORK_ROOT}/principal
        key_stash_file = ${WORK_ROOT}/.k5.${REALM}
        acl_file = ${WORK_ROOT}/kadm5.acl
        admin_keytab = ${WORK_ROOT}/kadm5.keytab
        max_life = 10h
        max_renewable_life = 7d
    }
EOF

: >"${WORK_ROOT}/kadm5.acl"

export KRB5_CONFIG="${KRB5_CONF}"
export KRB5_KDC_PROFILE="${KDC_CONF}"
export KRB5CCNAME="FILE:${CLIENT_CCACHE}"
export KRB5_KTNAME="FILE:${SERVICE_KEYTAB}"

kdb5_util create -s -P "naos-test-master-key" -r "${REALM}"
kadmin.local -r "${REALM}" -q "addprinc -randkey ${SERVICE_PRINCIPAL}"
kadmin.local -r "${REALM}" -q "ktadd -k ${SERVICE_KEYTAB} -norandkey ${SERVICE_PRINCIPAL}"
kadmin.local -r "${REALM}" -q "addprinc -randkey ${CLIENT_PRINCIPAL}"
kadmin.local -r "${REALM}" -q "ktadd -k ${CLIENT_KEYTAB} -norandkey ${CLIENT_PRINCIPAL}"

krb5kdc -n -r "${REALM}" -P "${WORK_ROOT}/krb5kdc.pid" >"${KDC_LOG}" 2>&1 &
KDC_PID=$!

for _ in $(seq 1 50); do
    if ! kill -0 "${KDC_PID}" 2>/dev/null; then
        cat "${KDC_LOG}" >&2
        exit 1
    fi
    if kinit -k -t "${CLIENT_KEYTAB}" "${CLIENT_PRINCIPAL}" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

if ! klist -s; then
    cat "${KDC_LOG}" >&2
    echo "failed to acquire Kerberos client credentials" >&2
    exit 1
fi

export NAOS_GSS_TEST_SERVICE_PRINCIPAL="${SERVICE_PRINCIPAL}"
export NAOS_GSS_TEST_CLIENT_PRINCIPAL="${CLIENT_PRINCIPAL}"

cargo test -p naos-nfs --features system-gss --test system_gss_real -- --nocapture
