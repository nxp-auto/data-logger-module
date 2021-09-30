# Copyright 2018-2021 NXP
# SPDX-License-Identifier: GPL-2.0
obj-m := bbox.o
bbox-y := bbox_main.o bbox_req_handlers.o bbox_api.o bbox_file.o \
	pcap_dump.o eth_pcap.o \
	can_ccap.o \
	pkt_dump.o \
	bb_server.o \
	u2k_thread.o

modules:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

modules_install: modules
	$(MAKE) -C $(KDIR) M=$(CURDIR) INSTALL_MOD_PATH=$(INSTALL_DIR) $@
	install -D bb_netlink.h $(INSTALL_DIR)/usr/include/bbox/bb_netlink.h
	install -D bb_msg.h $(INSTALL_DIR)/usr/include/bbox/bb_msg.h
	install -D bb_server.h $(INSTALL_DIR)/usr/include/bbox/bb_server.h
	install -D bbox_msg.h $(INSTALL_DIR)/usr/include/bbox/bbox_msg.h
	install -D bbox_api.h $(INSTALL_DIR)/usr/include/bbox/bbox_api.h
	install -D pkt_dump.h $(INSTALL_DIR)/usr/include/bbox/pkt_dump.h
	install -D bbox_server.h $(INSTALL_DIR)/usr/include/bbox/bbox_server.h
	install -D bbox_file.h $(INSTALL_DIR)/usr/include/bbox/bbox_file.h
	install -D coe.h $(INSTALL_DIR)/usr/include/bbox/coe.h
	install -D u2k_thread.h $(INSTALL_DIR)/usr/include/bbox/u2k_thread.h

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean