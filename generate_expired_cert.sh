#!/bin/sh

# this generates an already-expired certificate for testing in PCKS12 format.

set -e

# you can set the hostname if you want, but it'll default to localhost
if [ -z "$CERT_HOSTNAME" ]; then
    CERT_HOSTNAME="example.com"
fi

CERT_DIR="$(mktemp -d)/"

ALTNAME_FILE="${CERT_DIR}altnames.cnf"
CANAME_FILE="${CERT_DIR}ca.cnf"
CACERT="${CERT_DIR}ca.pem"
CAKEY="${CERT_DIR}cakey.pem"
CADB="${CERT_DIR}ca.txt"
CASRL="${CERT_DIR}ca.srl"

KEYFILE="${CERT_DIR}key.pem"
CERTFILE="${CERT_DIR}cert.pem"
CSRFILE="${CERT_DIR}cert.csr"
CHAINFILE="${CERT_DIR}chain.pem"
# DHFILE="${CERT_DIR}dh.pem"


cat > "${CANAME_FILE}" << DEVEOF
[req]
nsComment = "Certificate Authority"
distinguished_name  = req_distinguished_name
req_extensions = v3_ca

[ req_distinguished_name ]

countryName                     = Country Name (2 letter code)
countryName_default             = AU
countryName_min                 = 2
countryName_max                 = 2

stateOrProvinceName             = State or Province Name (full name)
stateOrProvinceName_default     = StateName

localityName                    = Locality Name (eg, city)
localityName_default            = CityName

0.organizationName              = Organization Name (eg, company)
0.organizationName_default      = INSECURE EXAMPLE

organizationalUnitName          = Organizational Unit Name (eg, section)
organizationalUnitName_default =  example org

commonName                      = Common Name (eg, your name or your server\'s hostname)
commonName_max                  = 64
commonName_default              = example.com

[ v3_ca ]
subjectKeyIdentifier = hash
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

DEVEOF

cat > "${ALTNAME_FILE}" << DEVEOF

[ca]
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = ${CERT_DIR}
certs             = ${CERT_DIR}
crl_dir           = ${CERT_DIR}
new_certs_dir     = ${CERT_DIR}
database          = ${CADB}
serial            = ${CASRL}

# The root key and root certificate.
private_key       = ${CAKEY}
certificate       = ${CACERT}

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 1
preserve          = no
policy            = policy_loose

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[req]
nsComment = "Certificate"
distinguished_name  = req_distinguished_name
req_extensions = v3_req

[ req_distinguished_name ]

countryName                     = Country Name (2 letter code)
countryName_default             = AU
countryName_min                 = 2
countryName_max                 = 2

stateOrProvinceName             = State or Province Name (full name)
stateOrProvinceName_default     = StateName

localityName                    = Locality Name (eg, city)
localityName_default            = CityName

0.organizationName              = Organization Name (eg, company)
0.organizationName_default      = INSECURE EXAMPLE

organizationalUnitName          = Organizational Unit Name (eg, section)
organizationalUnitName_default =  example org

commonName                      = Common Name (eg, your name or your server\'s hostname)
commonName_max                  = 64
commonName_default              = ${CERT_HOSTNAME}

[ v3_req ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "Server Certificate"
subjectKeyIdentifier = hash
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1

DEVEOF

touch "${CADB}"
echo 1000 > "${CASRL}"

echo "Make the ca key..."
openssl ecparam -genkey -name prime256v1 -noout -out "${CAKEY}"

echo "Self sign the CA..."
openssl req -batch -config "${CANAME_FILE}" \
    -key "${CAKEY}" \
    -new -x509 -days 1 \
    -sha256 -extensions v3_ca \
    -out "${CACERT}" \
    -nodes

echo "Generating the server private key..."
# openssl ecparam -genkey -name prime256v1 -noout -out "${KEYFILE}"

echo "Generating the certificate signing request..."
openssl req -sha256 -new \
    -batch \
    -days 1 \
    -config "${ALTNAME_FILE}" -extensions v3_req \
    -keyout "${KEYFILE}"\
    -nodes \
    -out "${CSRFILE}"

CERT_START="$(TZ=UTC date -v-3d +%y%m%d%H%M%SZ)"
CERT_EXPIRY="$(TZ=UTC date -v-1d +%y%m%d%H%M%SZ)"

echo "Signing the certificate..."
openssl ca -config "${ALTNAME_FILE}" \
    -batch \
    -extensions v3_req \
    -startdate "${CERT_START}" \
    -enddate "${CERT_EXPIRY}" \
    -notext -md sha256 \
    -in "${CSRFILE}" \
    -out "${CERTFILE}"

# Create the chain
# cat "${CERTFILE}" "${CACERT}" > "${CHAINFILE}"

openssl pkcs12 -export -out "./example.pfx" \
    -inkey "${KEYFILE}" \
    -in "${CERTFILE}" \
    -passout pass:password

# echo "Certificate chain is at: ${CHAINFILE}"
# echo "Private key is at: ${KEYFILE}"
echo "Expired-now cert at example.pfx and the password is 'password'"

rm -rf "${CERT_DIR}"

