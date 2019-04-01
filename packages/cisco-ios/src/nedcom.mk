SHELL = /bin/bash
CURRENT_DIR ?= $(shell pwd)

NS := namespaces
JAVA_PACKAGE=com.tailf.packages.ned.$(PACKAGE_NAME)
JDIR = $(shell echo $(JAVA_PACKAGE) | sed 's/\./\//g')
JFLAGS = --java-disable-prefix \
         --exclude-enums \
         --fail-on-warnings \
         --java-package $(JAVA_PACKAGE).$(NS) \
         --emit-java java/src/$(JDIR)/namespaces

YANG=$(wildcard yang/*.yang)
SUBMODULES = $(shell test -d yang && grep -l belongs-to yang/*.yang)
YANG_MODULES = $(filter-out $(SUBMODULES),$(YANG))

NED_ID_ARG = $(shell [ -x ${NCS_DIR}/support/ned-ncs-ned-id-arg ] && \
             ${NCS_DIR}/support/ned-ncs-ned-id-arg package-meta-data.xml.in)
ifeq ($(NED_ID_ARG),)
YANG_ID_MODULE ?= $(subst .yang,-id,$(MAIN_YANG_MODULE))
else
YANG_ID_MODULE = tailf-ned-id-$(shell echo $(NED_ID_ARG) | cut -d: -f2)
YANGPATH = --yangpath ncsc-out/modules/yang
endif

CONFIG_FXS := $(EXTRA_YANG_MODULES:%.yang=%.fxs) $(MAIN_YANG_MODULE:%.yang=%.fxs)
FXS := $(FXS) $(CONFIG_FXS) $(YANG_MODULES:yang/%.yang=ncsc-out/modules/fxs/%.fxs)

STATS_JAVA := $(if $(wildcard yang/$(subst .yang,-stats.yang,$(MAIN_YANG_MODULE))),java/src/$(JDIR)/namespaces/$(PACKAGE_NAME)Stats.java,)

JAVA_SRC := $(JAVA_SRC) $(shell find java/src -type f -name "*.java") java/src/$(JDIR)/namespaces/$(PACKAGE_NAME).java $(STATS_JAVA)

YANG_MAINMOD_JSON := $(EXTRA_YANG_MODULES:%.yang=artefacts/%.json) artefacts/$(subst .yang,,$(MAIN_YANG_MODULE)).json artefacts/cliparser-extensions-v11.json
YANG_MAINMOD_FLT := $(YANG_MAINMOD_JSON:artefacts/%.json=tmp-yang/%.yang.flt)

nedcom_cleaner = rm -rf artefacts ; \
		rm -rf tmp-yang ; \
		rm -f *.fxs ; \
		rm -f schema/jsondump.pyc

all_cli: NED_TYPE = cli-ned
all_gen: NED_TYPE = generic-ned

all_cli: ../package-meta-data.xml ned-id-file filter-yang $(YANG_MAINMOD_FLT) tmp-yang/$(MAIN_YANG_MODULE).clean \
	fxs $(YANG_MAINMOD_JSON) javac netsim nedcom_tidy
.PHONY: all_cli

all_gen: mkdirs ../package-meta-data.xml ned-id-file filter-yang fxs javac netsim nedcom_tidy
.PHONY: all_gen

mkdirs:
	mkdir -p ncsc-out/modules
	mkdir -p java/src/$(JDIR)/namespaces
	mkdir -p ../load-dir
	mkdir -p ../private-jar
	mkdir -p ../shared-jar
.PHONY: mkdirs

../package-meta-data.xml: package-meta-data.xml.in
	rm -rf $@
	if [ -x ${NCS_DIR}/support/ned-make-package-meta-data ]; then \
	   ${NCS_DIR}/support/ned-make-package-meta-data $<;          \
	else                                                          \
	   cp $< $@;                                                  \
	fi
	chmod +w $@

ned-id-file:
	if [ -x ${NCS_DIR}/support/ned-make-package-meta-data ]; then   \
	    echo -n "$(YANG_ID_MODULE) is built by: ";                  \
	    echo "support/ned-make-package-meta-data";                  \
	else                                                            \
	    $(NCSC) -c $(YANG_ID_MODULE).yang                           \
	        -o ../load-dir/$(YANG_ID_MODULE).fxs;                   \
	fi

javac:  $(JAVA_SRC)
	cd java && ant -q -Dpackage.name=$(PACKAGE_NAME) -Dpackage.dir=$(JDIR) all
.PHONY: javac

java/src/$(JDIR)/namespaces/$(PACKAGE_NAME).java: yang/$(MAIN_YANG_MODULE)
	$(NCSC) $(JFLAGS)/$(PACKAGE_NAME).java ncsc-out/modules/fxs/$(subst yang,fxs,$(MAIN_YANG_MODULE))

java/src/$(JDIR)/namespaces/$(PACKAGE_NAME)Stats.java: yang/$(subst .yang,-stats.yang,$(MAIN_YANG_MODULE))
	$(NCSC) $(JFLAGS)/$(PACKAGE_NAME)Stats.java ncsc-out/modules/fxs/$(subst .yang,-stats.fxs,$(MAIN_YANG_MODULE))

nedcom_tidy:
	rm -f ../load-dir/cliparser-extensions-v11.fxs
	@if [ "$(KEEP_FXS)" = "" -a `whoami` = jenkins ] ; then \
		$(nedcom_cleaner) ; \
	fi
.PHONY: nedcom_tidy

clean: nedcom_clean
	rm -rf ncsc-out/* ../load-dir/*
	rm -f ../package-meta-data.xml
	rm -f ../private-jar/$(PACKAGE_NAME).jar
	rm -f ../shared-jar/$(PACKAGE_NAME)-ns.jar
	rm -f java/src/$(JDIR)/$(NS)/*.java
	cd java && ant clean
	if [ -d "../netsim" ] ; then \
		cd ../netsim && $(MAKE) clean ; \
	fi
.PHONY: clean

nedcom_clean:
	$(nedcom_cleaner)
.PHONY: nedcom_clean

# Include standard NCS examples build definitions and rules
include $(NCS_DIR)/src/ncs/build/include.ncs.mk

include ned-yang-filter.mk

ncsc-out/modules/fxs:
	mkdir -p ncsc-out/modules/fxs

fxs: ncsc-out/modules/fxs $(FXS)
.PHONY: fxs

netsim:
	if [ -d "../netsim" ] ; then \
		(cd ../netsim && $(MAKE) all) \
	fi
.PHONY: fxs


ncsc-out/modules/fxs/%-meta.fxs: tmp-yang/%-meta.yang
	$(NCSC) $(YANGPATH) --yangpath yang -c $< -o $@
	cp $@ ../load-dir

ncsc-out/modules/fxs/%-oper.fxs: tmp-yang/%-oper.yang
	$(NCSC) $(YANGPATH) --yangpath yang -c $< -o $@
	cp $@ ../load-dir

ncsc-out/modules/fxs/%-secrets.fxs: tmp-yang/%-secrets.yang
	$(NCSC) --yangpath yang -c $< -o $@
	cp $@ ../load-dir

ncsc-out/modules/fxs/%-loginscripts.fxs: tmp-yang/%-loginscripts.yang
	$(NCSC) --yangpath yang -c $< -o $@
	cp $@ ../load-dir

$(CONFIG_FXS): %.fxs: tmp-yang/%.yang
	$(NCSC) --ncs-compile-module $< \
	  	--ncs-skip-statistics \
		--ncs-device-dir ncsc-out \
		--ncs-device-type $(NED_TYPE) \
		$(NED_ID_ARG) \
		${SUPPRESS_WARN}
	cp ncsc-out/modules/fxs/$@ ../load-dir

ncsc-out/modules/fxs/%.fxs: tmp-yang/%.yang
	$(NCSC) --ncs-compile-module $< \
	        --ncs-skip-config \
		--ncs-skip-template \
		--ncs-device-dir ncsc-out \
		--ncs-device-type $(NED_TYPE) \
		--yangpath yang \
		$(NED_ID_ARG) \
		${SUPPRESS_WARN}
	cp $@ ../load-dir

tmp-yang/%.flt: tmp-yang/%
	@if [ $(NCS_VER_NUMERIC) -lt 4040100 ]; then \
		cat $< | $(subst zzzREGEX,$(NED_DATA_YANG_REGEX),$(yang_cleaner)) | \
		$(subst zzzREGEX,$(NED_NEW_DIFF_DEPS_REGEX),$(yang_cleaner)) > $@ ; \
	else \
		cp $< $@ ; \
	fi

# This is only to filter out cliparser extensions when compiling into NSO .fxs to avoid versioning trouble
tmp-yang/$(MAIN_YANG_MODULE).clean: yang/$(MAIN_YANG_MODULE)
	cat tmp-yang/$(MAIN_YANG_MODULE) | \
		python -c 'import re, sys; s=sys.stdin.read(); s=re.sub("^.*import cliparser[^\\}]+\\}", "", s, flags=re.MULTILINE); s=re.sub("^\\s+cli:[a-z0-9\-]+([ \t]+((\"[^\"]+\")|([^\"]\\S+))\\s*)?((;)|(\{[^\}]+\}))","", s, flags=re.MULTILINE); print(s.strip())' \
		> tmp-yang/$(MAIN_YANG_MODULE).clean ; \
	cp tmp-yang/$(MAIN_YANG_MODULE).clean tmp-yang/$(MAIN_YANG_MODULE)
# Touch these to avoid dependecy triggering next build:
	touch tmp-yang/$(MAIN_YANG_MODULE).flt

artefacts/%.json: tmp-yang/%.yang.flt
	@mkdir -p artefacts
	@echo "GENERATE SCHEMA $@ FOR TURBO" ; \
	pyang -o $@ -p tmp-yang --json-pretty --json-cli $(PYANG_JSON_XARGS)  \
		--json-cli-module=cliparser-extensions-v11 --plugindir $(CURRENT_DIR)/schema/ -f json $<
