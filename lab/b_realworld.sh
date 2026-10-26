#!/bin/bash
# Paper B external check: handshake sizes against public servers, classical vs hybrid group list
# (OpenSSL 4.0.3 s_client, TLS 1.3, one HEAD request per connection, 3 repetitions).
B=${LAB:-/opt/p1920b}; export LD_LIBRARY_PATH=$B/ossl4/lib; O=$B/ossl4/bin/openssl
OUT=$B/realworld; mkdir -p $OUT; cd $OUT; : > results.tsv
IF=$(ip route show default | awk '{print $5; exit}')
for site in www.cloudflare.com www.google.com www.facebook.com github.com www.wikipedia.org www.amazon.com www.microsoft.com www.apple.com; do
  for kx in classical hybrid; do for r in 1 2 3; do
    G=""; [ $kx = classical ] && G="-groups X25519:P-256:X448:P-521:P-384"
    P=$OUT/${site}_${kx}_$r.pcap
    tcpdump -i $IF -w $P -U -s 0 "tcp port 443 and host $site" >/dev/null 2>&1 & TP=$!; sleep 1
    RES=$(printf "HEAD / HTTP/1.1\r\nHost: $site\r\nConnection: close\r\n\r\n" | timeout 10 $O s_client -connect $site:443 -servername $site -tls1_3 -alpn http/1.1 $G -ign_eof 2>&1 | tr -d '\000')
    sleep 1; kill $TP; wait $TP 2>/dev/null
    GRP=$(echo "$RES" | grep -m1 -o -E "Negotiated TLS1.3 group: [A-Za-z0-9]+|Server Temp Key: [A-Za-z0-9]+" | awk '{print $NF}')
    SIG=$(echo "$RES" | grep -m1 -o -E "Peer signature type: [a-z0-9_]+" | awk '{print $NF}')
    printf "%s\t%s\t%s\t%s\t%s\t%s\n" $site $kx $r "$GRP" "$SIG" $P >> results.tsv
  done; done
done
cat results.tsv | cut -f1-5
