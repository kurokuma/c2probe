.PHONY: check test build package

check:
	cargo fmt --all -- --check
	cargo clippy --locked --all-targets -- -D warnings

test:
	cargo test --locked --all-targets

build: check test
	cargo build --locked --release

package:
	./scripts/build-linux.sh

