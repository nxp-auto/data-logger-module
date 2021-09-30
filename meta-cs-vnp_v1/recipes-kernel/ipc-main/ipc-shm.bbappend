module_do_install_append() {
        install -d ${D}/usr/include/ipc-shm
        cp -f ${S}/ipc-shm.h ${D}/usr/include/ipc-shm/
}