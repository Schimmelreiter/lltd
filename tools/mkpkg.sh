#!/bin/sh
# Builds a .deb (Debian) or .ipk (OpenEmbedded/OpenATV, ar format) from a
# staged root directory. Used by the GitHub workflow.
#
#   tools/mkpkg.sh deb|ipk NAME VERSION ARCH ROOTDIR OUTDIR "DESCRIPTION" \
#       [-d DEPENDS] [-s SCRIPTDIR] [-c CONFFILE ...]
#
# SCRIPTDIR may contain postinst, prerm, postrm (copied into the control part).

set -eu

fmt=$1 name=$2 version=$3 arch=$4 root=$5 outdir=$6 desc=$7
shift 7
depends="" scripts="" conffiles=""
while [ $# -gt 0 ]; do
	case "$1" in
		-d) depends=$2; shift 2 ;;
		-s) scripts=$2; shift 2 ;;
		-c) conffiles="$conffiles $2"; shift 2 ;;
		*) echo "unknown option $1" >&2; exit 2 ;;
	esac
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/control" "$outdir"
size=$(du -sk "$root" | cut -f1)

{
	echo "Package: $name"
	echo "Version: $version"
	echo "Architecture: $arch"
	echo "Maintainer: Schimmelreiter <https://github.com/Schimmelreiter>"
	echo "Section: net"
	echo "Priority: optional"
	[ -n "$depends" ] && echo "Depends: $depends"
	echo "Installed-Size: $size"
	echo "Homepage: https://github.com/Schimmelreiter/$name"
	echo "Description: $desc"
} > "$work/control/control"

for f in $conffiles; do
	echo "$f" >> "$work/control/conffiles"
done
if [ -n "$scripts" ]; then
	for s in preinst postinst prerm postrm; do
		[ -f "$scripts/$s" ] && install -m 0755 "$scripts/$s" "$work/control/$s"
	done
fi

case "$fmt" in
deb)
	mkdir -p "$work/pkg"
	cp -a "$root/." "$work/pkg/"
	mkdir -p "$work/pkg/DEBIAN"
	cp -a "$work/control/." "$work/pkg/DEBIAN/"
	out="$outdir/${name}_${version}_${arch}.deb"
	dpkg-deb --root-owner-group -Zxz -b "$work/pkg" "$out" >/dev/null
	;;
ipk)
	echo "2.0" > "$work/debian-binary"
	(cd "$work/control" && tar --owner=0 --group=0 --numeric-owner -czf ../control.tar.gz ./*)
	(cd "$root" && tar --owner=0 --group=0 --numeric-owner -czf "$work/data.tar.gz" .)
	out="$outdir/${name}_${version}_${arch}.ipk"
	rm -f "$out"
	(cd "$work" && ar rc "$(cd "$(dirname "$out")" && pwd)/$(basename "$out")" debian-binary control.tar.gz data.tar.gz)
	;;
*)
	echo "format must be deb or ipk" >&2
	exit 2
	;;
esac
echo "$out"
