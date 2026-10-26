#!/bin/bash
B=${LAB:-/opt/p1920b}; export LD_LIBRARY_PATH=$B/ossl4/lib; O=$B/ossl4/bin/openssl; T=$B/gotls/tlslab
grep -q www.example.test /etc/hosts || echo "10.0.0.1 www.example.test public.example.test" >> /etc/hosts
cd $B/pki
[ -f srv_mldsa_seed.key ] || $O pkey -in srv_mldsa.key -provparam ml-dsa.output_formats=seed-only -out srv_mldsa_seed.key
cp srv_ecdsa.key srv_ecdsa_seed.key
$T echimport -in $B/pki/ech.pem -out $B/pki/ech
ECL=$(cat $B/pki/ech/ech_configlist.b64)
for alg in ecdsa mldsa; do
  $T server -cert $B/pki/srv_$alg.crt -key $B/pki/srv_${alg}_seed.key -ech $B/pki/ech -addr 127.0.0.1:443 >/tmp/gosrv_$alg.log 2>&1 &
  SP=$!; sleep 1
  for kx in classical hybrid; do for e in "" "$B/pki/ech"; do
    R=$(timeout 20 $T client -profile probe -target 127.0.0.1 -kx $kx -ca $B/pki/ca_$alg.crt ${e:+-ech $e} 2>&1 | tail -1)
    echo "go-client $alg $kx ech=${e:+1} :: $R"
  done; done
  for grp in X25519 X25519MLKEM768; do for ech in 0 1; do
    CA=""; [ $ech = 1 ] && CA="-ech_config_list $ECL"
    OUT=$(printf 'GET /obj?n=5000 HTTP/1.1\r\nHost: www.example.test\r\nConnection: close\r\n\r\n' | timeout 5 $O s_client -connect 127.0.0.1:443 -servername www.example.test -groups $grp -tls1_3 -alpn http/1.1 -CAfile $B/pki/ca_$alg.crt $CA -ign_eof 2>/dev/null | tr -d '\000')
    echo "openssl-client $alg $grp ech=$ech :: $(echo "$OUT" | grep -E -m1 'Negotiated TLS1.3 group') | $(echo "$OUT" | grep -E -m1 'Peer signature type') | $(echo "$OUT" | grep -E -m1 'ECH:') | $(echo "$OUT" | grep -m1 -o 'Verify return code: [0-9]*') | $(echo "$OUT" | grep -m1 'HTTP/1.1')"
  done; done
  kill $SP 2>/dev/null; wait $SP 2>/dev/null; tail -2 /tmp/gosrv_$alg.log
done
