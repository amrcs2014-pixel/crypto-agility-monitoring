#!/bin/bash
B=${LAB:-/opt/p1920b}; export LD_LIBRARY_PATH=$B/ossl4/lib; O=$B/ossl4/bin/openssl
mkdir -p $B/pki && cd $B/pki
# ECDSA P-256 and ML-DSA-65 server certificates (self-signed CA each)
for alg in ecdsa mldsa; do
  if [ $alg = ecdsa ]; then K="-newkey ec -pkeyopt ec_paramgen_curve:P-256"; else K="-newkey ML-DSA-65"; fi
  $O req -x509 $K -nodes -days 3650 -subj "/CN=Test CA $alg" -keyout ca_$alg.key -out ca_$alg.crt 2>/dev/null
  $O req $K -nodes -subj "/CN=www.example.test" -keyout srv_$alg.key -out srv_$alg.csr 2>/dev/null
  printf "subjectAltName=DNS:www.example.test,DNS:public.example.test\n" > ext.cnf
  $O x509 -req -in srv_$alg.csr -CA ca_$alg.crt -CAkey ca_$alg.key -CAcreateserial -days 3650 -extfile ext.cnf -out srv_$alg.crt 2>/dev/null
  echo "$alg cert bytes: $(wc -c < srv_$alg.crt) (PEM)"
done
$O ech -help 2>&1 | head -12
echo "=== handshakes"
openssl_ech=$B/pki/ech.pem
[ -f $openssl_ech ] || $O ech -public_name public.example.test -out $openssl_ech >/dev/null 2>&1
ECHCFG=$(sed -n '/BEGIN ECHCONFIG/,/END ECHCONFIG/p' $openssl_ech | grep -v -- '-----' | tr -d '\n')
echo "echconfig b64 len ${#ECHCFG}"
mkdir -p $B/www; head -c 20000 /dev/urandom | base64 > $B/www/index.html
for alg in ecdsa mldsa; do for grp in X25519 X25519MLKEM768; do for ech in 0 1; do
  cd $B/www
  EA=""; [ $ech = 1 ] && EA="-ech_key $openssl_ech"
  $O s_server -accept 14433 -WWW -cert $B/pki/srv_$alg.crt -key $B/pki/srv_$alg.key -groups X25519MLKEM768:X25519 $EA -quiet >/tmp/srv.log 2>&1 &
  SP=$!; sleep 0.6
  CA=""; [ $ech = 1 ] && CA="-ech_config_list $ECHCFG"
  OUT=$(printf 'GET /index.html HTTP/1.0\r\n\r\n' | timeout 5 $O s_client -connect 127.0.0.1:14433 -servername www.example.test -groups $grp -CAfile $B/pki/ca_$alg.crt $CA -ign_eof 2>&1)
  echo "$alg $grp ech=$ech :: $(echo "$OUT" | grep -E -m1 'Negotiated TLS1.3 group|Server Temp Key') | $(echo "$OUT" | grep -E -m1 'Peer signature type') | $(echo "$OUT" | grep -E -m1 -i 'ECH:|ech status') | verify=$(echo "$OUT" | grep -m1 -o 'Verify return code: [0-9]*') | bytes=$(echo "$OUT" | wc -c)"
  kill $SP 2>/dev/null; wait $SP 2>/dev/null
done; done; done
