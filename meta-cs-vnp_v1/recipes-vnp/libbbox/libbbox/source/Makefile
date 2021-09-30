# Copyright 2018-2021 NXP
# SPDX-License-Identifier: BSD-3-Clause
USR_INCDIR ?= /usr/include
EXT_CFLAGS := -g -O2 -Wall \
		-fPIC \
		-I$(USR_INCDIR)/bbox

SRC_DIRS := 

SRCS_C := \
	bb_msg.c \
	bbox_client.c \
	bbox_disk.c \
	bash_command.c

SRCS_C += $(foreach d, $(SRC_DIRS), $(wildcard $d/*.c))

OBJS_C := $(SRCS_C:.c=.o)
.PHONEY: all
all: bbox_test u2k

bbox_test: bbox_test_main.o libbbox.so
	$(CC) -o $@ $^ $(LDFLAGS)

libbbox.so: $(OBJS_ASM) $(OBJS_C) $(OBJS_CXX)
	$(CC) -shared -Wl,-soname,$@ -o $@ $^

u2k: u2k.o
	$(CC) -o $@ $^ $(LDFLAGS)

install:
	install -d $(DESTDIR)/usr/bin
	install -m 0755 bbox_test $(DESTDIR)/usr/bin
	install -m 0755 u2k $(DESTDIR)/usr/bin
	install -d $(DESTDIR)/usr/lib
	install -m 0644 libbbox.so $(DESTDIR)/usr/lib
	install -d $(DESTDIR)/usr/include/bbox
	install -m 0644 bbox_*.h $(DESTDIR)/usr/include/bbox

clean:
	$(RM) bbox_test_main.o u2k.o u2k bbox_test libbbox.so
	$(RM) $(OBJS_ASM) $(OBJS_C) $(OBJS_CXX)
	$(RM) $(OBJS_C:.o=.d) $(OBJS_CXX:.o=.d)

ifeq ($(findstring clean, $(MAKECMDGOALS)),)
-include $(SRCS_C:.c=.d) uds_main.d
endif

$(OBJS_C) bbox_test_main.o u2k.o : %.o : %.c
	$(CC) -c -MD $(CFLAGS) $(EXT_CFLAGS) $< -o $@
 