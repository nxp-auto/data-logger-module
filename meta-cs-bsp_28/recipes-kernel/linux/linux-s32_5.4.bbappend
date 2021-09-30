FILESEXTRAPATHS_prepend := "${THISDIR}/${BPN}:"
SRC_URI += " \
	file://0001-dts-for-ipcf-and-disable-qspi.patch \
	file://0001-add-mdio-pinctrl-for-gmac.patch \
	file://build/usbwifi-rtl81xx.cfg \
"
SRC_URI += "\
	file://build/nvme.cfg \
	"
DELTA_KERNEL_DEFCONFIG_append += "\
	nvme.cfg \
	"
DELTA_KERNEL_DEFCONFIG_append += "${@bb.utils.contains('DISTRO_FEATURES', 'usbwifi-rtl81xx', 'usbwifi-rtl81xx.cfg', '', d)}"
