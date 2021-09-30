# Copyright 2021 NXP
# SPDX-License-Identifier:	BSD-3-Clause
SUMMARY = "some common library for application"
LICENSE = "BSD-3-Clause"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/BSD-3-Clause;md5=550794465ba0ec5312d6919e203a55f9"

SRC_URI = " \
	file://source \
	"
DEPENDS = "kbbox"
RDEPENDS_${PN} = "python3-core"

S = "${WORKDIR}/source"

EXTRA_OEMAKE_append = " DESTDIR=${D} USR_INCDIR=\"${STAGING_INCDIR}\""

do_install() {
    oe_runmake install
	cd ${D}${libdir} && ln -s libbbox.so libbbox.so.1
	install -m 0755 ${S}/python/* ${D}${bindir}
}

FILES_${PN} = "${includedir}/* ${libdir}/lib*.so ${bindir}/*"
FILES_${PN}-dev = "${libdir}/lib*.so.1"
INSANE_SKIP_${PN} = "ldflags"
INSANE_SKIP_${PN}-dev = "ldflags"
