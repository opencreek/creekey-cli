# Maintainer: Opencreek Technogoly UG
pkgname=creekey
pkgver=0.1.0
pkgrel=1
makedepends=('rust' 'cargo')
arch=('i686' 'x86_64' 'armv6h' 'armv7h')
pkgdesc="Story your Private Keys on your Phone!"
url="https://creekey.io"
license=('UNLICENSED')

build() {
    return 0
}

package() {
    cd $srcdir
    cargo install --root="$pkgdir" --git=https://github.com/opencreek/creekey-cli --branch=main
}
