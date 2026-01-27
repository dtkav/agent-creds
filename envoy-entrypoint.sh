#!/bin/sh
set -e

CA_CRT="/certs/ca.crt"
CA_KEY="/certs/ca.key"
CERT_DIR="/tmp/certs"

mkdir -p "$CERT_DIR"

# Extract hosts from domains.json (simple JSON array of {host, auth_type})
grep '"host"' /etc/envoy/domains.json | sed 's/.*"host": *"//;s/".*//' | while read -r host; do
    safename=$(echo "$host" | tr '.' '_')
    keyfile="$CERT_DIR/${safename}.key"
    crtfile="$CERT_DIR/${safename}.crt"
    csrfile="$CERT_DIR/${safename}.csr"
    extfile="$CERT_DIR/${safename}.ext"

    openssl genrsa -out "$keyfile" 2048 2>/dev/null

    openssl req -new -key "$keyfile" -out "$csrfile" \
        -subj "/CN=${host}" 2>/dev/null

    printf "subjectAltName=DNS:%s\n" "$host" > "$extfile"

    openssl x509 -req -days 365 \
        -in "$csrfile" \
        -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
        -extfile "$extfile" \
        -out "$crtfile" 2>/dev/null

    rm -f "$csrfile" "$extfile"
done

exec envoy "$@"
