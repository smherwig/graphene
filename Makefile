SYS ?= $(shell gcc -dumpmachine)
export SYS

targets = all clean format

.PHONY: $(targets)
$(targets):
	$(MAKE) -C Pal $@
	$(MAKE) -C LibOS $@
	$(MAKE) -C Runtime $@
	#$(MAKE) -C bearssl-0.6 $@

.PHONY: install
install:
	@echo "\"make install\" is deprecated. use \"make\" instead."
