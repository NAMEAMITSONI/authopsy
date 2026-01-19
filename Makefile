.PHONY: build install uninstall clean test deb release

PREFIX ?= /usr/local
BINARY = authopsy
VERSION = 1.0.0

build:
	cargo build --release

install: build
	install -d $(PREFIX)/bin
	install -m 755 target/release/$(BINARY) $(PREFIX)/bin/$(BINARY)
	@echo "Installed to $(PREFIX)/bin/$(BINARY)"

uninstall:
	rm -f $(PREFIX)/bin/$(BINARY)
	@echo "Removed $(PREFIX)/bin/$(BINARY)"

clean:
	cargo clean
	rm -rf *.deb $(BINARY)_*

test:
	cargo test

deb: build
	@bash scripts/build-deb.sh

release: clean test build
	@echo "Release build complete: target/release/$(BINARY)"
