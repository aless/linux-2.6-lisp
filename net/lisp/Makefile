#
# Makefile for the LISP.
#

ifeq ($(CONFIG_LISP_DEBUG),1)
LISP_DBG_FLAGS := -DDEBUG
endif

ccflags-y := $(LISP_DBG_FLAGS)

lisp-objs += lisp_dev.o map_semantics.o map_trie.o

obj-$(CONFIG_LISP) += lisp.o
