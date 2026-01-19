#!/bin/bash
set -e

VERSION="1.0.0"
ARCH=$(dpkg --print-architecture)
PKG_NAME="authopsy"
PKG_DIR="${PKG_NAME}_${VERSION}_${ARCH}"

cargo build --release

rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/local/bin"

cp target/release/authopsy "$PKG_DIR/usr/local/bin/"

cat > "$PKG_DIR/DEBIAN/control" << EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: security
Priority: optional
Architecture: ${ARCH}
Maintainer: Burak Ozcan <burak@example.com>
Description: RBAC vulnerability scanner for REST APIs
 High-performance CLI tool for testing authorization vulnerabilities.
 Compares API responses across Admin, User, and Anonymous roles.
Homepage: https://github.com/burakozcn01/authopsy
EOF

dpkg-deb --build "$PKG_DIR"

echo "Package created: ${PKG_DIR}.deb"
echo "Install with: sudo dpkg -i ${PKG_DIR}.deb"
