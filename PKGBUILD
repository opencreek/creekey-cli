pkgname=creekey
pkgver=0.1.0
pkgrel=1
makedepends=('rust' 'cargo')
arch=('i686' 'x86_64' 'armv6h' 'armv7h')

build() {
    return 0
}

package() {
    cargo install --root="$pkgdir" creekey
}

build() {
    export RUSTUP_TOOLCHAIN=stable
    export CARGO_TARGET_DIR=target
    cargo build --frozen --release --all-features
}
#
# prepare() {
#     cargo fetch --locked --target "$CARCH-unknown-linux-gnu"
# }
