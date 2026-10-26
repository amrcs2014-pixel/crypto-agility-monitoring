#!/bin/bash
# Build the TLS stacks for Paper B under /opt/p1920b (no spaces in paths).
set -e
B=${LAB:-/opt/p1920b}; mkdir -p $B/src; cd $B/src
log(){ echo "[$(date +%T)] $*"; }
if [ ! -x $B/go/bin/go ]; then
  log "go"; curl -sL https://go.dev/dl/go1.27.1.linux-amd64.tar.gz -o go.tgz; tar -C $B -xzf go.tgz; fi
$B/go/bin/go version
if [ ! -x $B/ossl4/bin/openssl ]; then
  log "openssl 4.0.3"; curl -sL https://github.com/openssl/openssl/releases/download/openssl-4.0.3/openssl-4.0.3.tar.gz -o ossl.tgz
  tar xzf ossl.tgz; cd openssl-4.0.3
  ./Configure --prefix=$B/ossl4 --libdir=lib no-docs no-tests -Wl,-rpath,$B/ossl4/lib >/dev/null
  make -j10 >/dev/null 2>&1; make install_sw >/dev/null; cd ..; fi
LD_LIBRARY_PATH=$B/ossl4/lib $B/ossl4/bin/openssl version
if [ ! -x $B/curl/bin/curl ]; then
  log "curl"; curl -sL https://curl.se/download/curl-8.16.0.tar.gz -o curl.tgz; tar xzf curl.tgz; cd curl-8.16.0
  ./configure --prefix=$B/curl --with-openssl=$B/ossl4 --without-libpsl --disable-ldap --without-brotli --without-zstd --without-libidn2 --without-nghttp2 LDFLAGS="-Wl,-rpath,$B/ossl4/lib" >/dev/null
  make -j10 >/dev/null 2>&1; make install >/dev/null; cd ..; fi
$B/curl/bin/curl --version | head -2
log "done"
