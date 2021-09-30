# Copyright 2018-2021 NXP
# SPDX-License-Identifier:	GPL-2.0
SUMMARY = "kernel application for bbox"
LICENSE = "GPL-2.0"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/GPL-2.0;md5=801f80980d171dd6425610833a22dbe6"

inherit module

SRC_URI = "file://source/"

S = "${WORKDIR}/source"
EXTRA_OEMAKE_append = " KDIR=${KBUILD_OUTPUT} INSTALL_DIR=${D}"

#KERNEL_MODULE_AUTOLOAD += "bbox"

FILES_${PN} += "${base_libdir}/*"
FILES_${PN} += "${sysconfdir}/modules-load.d/*"

PROVIDES = "kernel-module-bbox${KERNEL_MODULE_PACKAGE_SUFFIX}"
RPROVIDES_${PN} = "kernel-module-bbox${KERNEL_MODULE_PACKAGE_SUFFIX}"

COMPATIBLE_MACHINE = "gen1"

