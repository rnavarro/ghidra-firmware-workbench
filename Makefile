# Ghidra firmware workbench
#
# GHIDRA defaults to a local 12.1.4 install. Override it for another version:
#   make GHIDRA=~/opt/ghidra_12.1.5_PUBLIC verify-extensions

GHIDRA ?= $(HOME)/opt/ghidra_12.1.4_PUBLIC

# Extension zips ship inside the distribution, uninstalled. Ghidra only loads an
# extension once it has been unpacked into Ghidra/Extensions/, and that directory
# is not covered by any other check, so it is a real source of drift between one
# machine and another.
EXT_ZIPS := $(GHIDRA)/Extensions/Ghidra
EXT_DEST := $(GHIDRA)/Ghidra/Extensions
# Extensions this workbench expects to be installed. Most shipped extensions are
# optional and absent by default, so recording the intended set is what makes
# `verify-extensions` a drift check rather than a list of everything on offer.
EXT_WANT := extensions.want

.PHONY: help extensions verify-extensions list-extensions

help:
	@echo "targets:"
	@echo "  list-extensions    show extension zips shipped with this Ghidra"
	@echo "  extensions         unpack EXTENSION=<name> (or all) into Ghidra/Extensions"
	@echo "  verify-extensions  report which shipped extensions are installed"
	@echo ""
	@echo "GHIDRA=$(GHIDRA)"

list-extensions:
	@ls -1 $(EXT_ZIPS)/*.zip 2>/dev/null \
		| sed 's|.*/||; s|^ghidra_[0-9.]*_PUBLIC_[0-9]*_||; s|\.zip$$||' \
		| sort

# Install one extension: make extensions EXTENSION=MachineLearning
# Or every shipped extension: make extensions EXTENSION=all
extensions:
	@test -d $(EXT_ZIPS) || { echo "no extension zips at $(EXT_ZIPS)"; exit 1; }
	@test -n "$(EXTENSION)" || { \
		echo "set EXTENSION=<name>, or EXTENSION=all"; \
		echo "available:"; $(MAKE) --no-print-directory list-extensions; exit 1; }
	@mkdir -p $(EXT_DEST)
	@if [ "$(EXTENSION)" = "all" ]; then \
		for z in $(EXT_ZIPS)/*.zip; do \
			echo "unpacking $$(basename $$z)"; \
			unzip -qo "$$z" -d $(EXT_DEST); \
		done; \
	else \
		z=$$(ls $(EXT_ZIPS)/*_$(EXTENSION).zip 2>/dev/null | head -1); \
		test -n "$$z" || { echo "no zip for $(EXTENSION)"; exit 1; }; \
		echo "unpacking $$(basename $$z)"; \
		unzip -qo "$$z" -d $(EXT_DEST); \
	fi
	@echo "---"
	@echo "installed into $(EXT_DEST). Restart Ghidra for extensions to load."

verify-extensions:
	@echo "Ghidra: $(GHIDRA)"
	@test -f $(EXT_WANT) || { echo "no $(EXT_WANT)"; exit 1; }
	@fail=0; while read -r name; do \
		case "$$name" in ''|\#*) continue;; esac; \
		if [ -d "$(EXT_DEST)/$$name" ]; then \
			echo "installed  $$name"; \
		else \
			echo "MISSING    $$name"; fail=1; \
		fi; \
	done < $(EXT_WANT); \
	if [ $$fail -eq 1 ]; then \
		echo ""; echo "run: make extensions EXTENSION=<name>"; exit 1; \
	fi
	@echo "all wanted extensions installed"
