FILESEXTRAPATHS_prepend := "${THISDIR}/${BPN}:"
SRC_URI += " \
	file://0001-add-ipc-vnet-node.patch \
"
SRC_URI += "\
	file://build/nvme.cfg \
	"
DELTA_KERNEL_DEFCONFIG_append += "\
	nvme.cfg \
	"
