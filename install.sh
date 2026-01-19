#!/bin/bash
set -e

REPO="burakozcn01/authopsy"
INSTALL_DIR="/usr/local/bin"
BINARY="authopsy"

get_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "x86_64" ;;
        arm64|aarch64) echo "aarch64" ;;
        *) echo "unsupported"; exit 1 ;;
    esac
}

get_os() {
    case "$(uname -s)" in
        Linux) echo "unknown-linux-gnu" ;;
        Darwin) echo "apple-darwin" ;;
        *) echo "unsupported"; exit 1 ;;
    esac
}

get_latest_version() {
    curl -sI "https://github.com/$REPO/releases/latest" | \
        grep -i "location:" | \
        sed 's/.*tag\///' | \
        tr -d '\r\n'
}

download_binary() {
    local version=$1
    local target=$2
    local url="https://github.com/$REPO/releases/download/${version}/authopsy-${target}.tar.gz"

    echo "Downloading from: $url"

    local tmp_dir=$(mktemp -d)
    curl -sL "$url" | tar xz -C "$tmp_dir"

    if [ -f "$tmp_dir/authopsy" ]; then
        sudo install -m 755 "$tmp_dir/authopsy" "$INSTALL_DIR/$BINARY"
        rm -rf "$tmp_dir"
        return 0
    fi

    rm -rf "$tmp_dir"
    return 1
}

build_from_source() {
    echo "Building from source..."

    if [ -f "Cargo.toml" ]; then
        cargo build --release
        sudo install -m 755 target/release/$BINARY $INSTALL_DIR/$BINARY
    else
        cargo install --git https://github.com/$REPO
    fi
}

main() {
    local arch=$(get_arch)
    local os=$(get_os)
    local target="${arch}-${os}"

    echo "Detected platform: $target"
    echo ""

    local version=$(get_latest_version)

    if [ -n "$version" ]; then
        echo "Latest version: $version"

        if download_binary "$version" "$target" 2>/dev/null; then
            echo ""
            echo "Installed successfully!"
            echo "Run: authopsy --help"
            exit 0
        fi

        echo "Pre-built binary not available for $target"
    fi

    if command -v cargo &> /dev/null; then
        build_from_source
        echo ""
        echo "Installed successfully!"
        echo "Run: authopsy --help"
    else
        echo ""
        echo "No pre-built binary available and Rust not found."
        echo ""
        echo "Option 1 - Install Rust and build from source:"
        echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        echo "  cargo install --git https://github.com/$REPO"
        echo ""
        echo "Option 2 - Download binary manually:"
        echo "  https://github.com/$REPO/releases"
        exit 1
    fi
}

main
