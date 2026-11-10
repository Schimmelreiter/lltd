SUMMARY = "Link Layer Topology Discovery (LLTD) responder"
DESCRIPTION = "Makes the receiver appear in the Windows network map and in \
LLTD mappers (name, address, medium, speed, icon) and answers topology tests."
HOMEPAGE = "https://github.com/Schimmelreiter/lltd"

LICENSE = "GPL-3.0-or-later"
LIC_FILES_CHKSUM = "file://LICENSE;md5=1ebbd3e34237af26da5dc08a4e440464"

SRC_URI = "git://github.com/Schimmelreiter/lltd.git;protocol=https;branch=master"
SRCREV = "b3a3a74f0827f668d5dfaf3ac3be0225fb7d84e1"
PV = "1.0.0+git"

# OE 5.1 and newer (UNPACKDIR, like oe-alliance 6.0); older releases: ${WORKDIR}/git
S = "${UNPACKDIR}/git"

inherit update-rc.d

EXTRA_OEMAKE = "CC='${CC}' CFLAGS='${CFLAGS}' LDFLAGS='${LDFLAGS}' VERSION='1.0.0'"

do_compile() {
    oe_runmake lltd
}

do_install() {
    install -D -m 0755 ${S}/lltd ${D}${sbindir}/lltd
    install -D -m 0755 ${S}/files/sysv/lltd.init ${D}${sysconfdir}/init.d/lltd
    install -D -m 0644 ${S}/files/sysv/lltd.default ${D}${sysconfdir}/default/lltd
}

CONFFILES:${PN} = "${sysconfdir}/default/lltd"

INITSCRIPT_NAME = "lltd"
INITSCRIPT_PARAMS = "defaults 60"
