ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

.PHONY: all
all: oabe_dec.manifest
ifeq ($(SGX),1)
all: oabe_dec.manifest.sgx oabe_dec.sig
endif

oabe_dec.manifest: manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Dexecdir=/home/sunanda/Downloads/tee_sgx/edge_offload/v4/data_exchange \
		-Darch_libdir=$(ARCH_LIBDIR) \
		$< >$@

oabe_dec.manifest.sgx: oabe_dec.manifest
	gramine-sgx-sign \
		--manifest oabe_dec.manifest \
		--output $@

oabe_dec.sig: oabe_dec.manifest.sgx

ifeq ($(SGX),)
GRAMINE = gramine-direct
else
GRAMINE = gramine-sgx
endif

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig

.PHONY: distclean
distclean: clean
