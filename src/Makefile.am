## Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = serial-tests
bin_PROGRAMS = iotchain-core

include $(top_srcdir)/common.mk
include $(srcdir)/src.mk

noinst_HEADERS = $(SRC_H_FILES)

if BUILD_TESTS
iotchain_core_SOURCES = main/IOTChainCoreVersion.cpp $(SRC_CXX_FILES) $(SRC_TEST_CXX_FILES)
else # !BUILD_TESTS
iotchain_core_SOURCES = main/IOTChainCoreVersion.cpp $(SRC_CXX_FILES)
endif # !BUILD_TESTS

iotchain_core_LDADD = $(soci_LIBS) $(libmedida_LIBS)		\
	$(top_builddir)/lib/lib3rdparty.a $(sqlite3_LIBS)	\
	$(libpq_LIBS) $(xdrpp_LIBS) $(libsodium_LIBS)

TESTDATA_DIR = testdata
TEST_FILES = $(TESTDATA_DIR)/iotchain-core_example.cfg $(TESTDATA_DIR)/iotchain-core_standalone.cfg \
             $(TESTDATA_DIR)/iotchain-core_testnet.cfg $(TESTDATA_DIR)/iotchain-core_testnet_legacy.cfg \
	     $(TESTDATA_DIR)/iotchain-history.testnet.6714239.json $(TESTDATA_DIR)/iotchain-history.livenet.15686975.json $(TESTDATA_DIR)/iotchain-core_example_validators.cfg

BUILT_SOURCES = $(SRC_X_FILES:.x=.h) main/IOTChainCoreVersion.cpp $(TEST_FILES)

SUFFIXES = .x .h
.x.h: $(XDRC)
	$(XDRC) -hh -o $@ $<

$(srcdir)/src.mk: $(top_srcdir)/make-mks
	cd $(top_srcdir) && ./make-mks

$(TESTDATA_DIR)/%.cfg : $(top_srcdir)/docs/%.cfg
	mkdir -p $(@D) && cp $< $@

$(TESTDATA_DIR)/%.json : $(top_srcdir)/src/history/serialize-tests/%.json
	mkdir -p $(@D) && cp $< $@

.PHONY: always
always:
	@:

# Always rebuild because .git/HEAD is a symbolic ref one can't depend on
main/IOTChainCoreVersion.cpp: always
	@vers=$$(cd "$(srcdir)" \
		&& git describe --always --dirty --tags 2>/dev/null \
		|| echo "$(PACKAGE) $(VERSION)"); \
		sed -e "s/%%VERSION%%/$$vers/" \
			< "$(srcdir)/main/IOTChainCoreVersion.cpp.in" > $@~
	@if cmp -s $@~ $@; then rm -f $@~; else \
	    mv -f $@~ $@ && printf "echo '%s' > $@\n" "$$(cat $@)"; fi

if USE_POSTGRES
TESTS=test/selftest-pg
else # !USE_POSTGRES
TESTS=test/selftest-nopg
endif # !USE_POSTGRES

if USE_CLANG_FORMAT
format: always
	cd $(srcdir) && $(CLANG_FORMAT) -style=file -i $(SRC_CXX_FILES) $(SRC_H_FILES) $(SRC_TEST_CXX_FILES) $(SRC_TEST_H_FILES)
endif # USE_CLANG_FORMAT

if USE_AFL_FUZZ
fuzz-testcases: iotchain-core
	mkdir -p fuzz-testcases
	for i in `seq 1 10`; do \
	    ./iotchain-core gen-fuzz fuzz-testcases/fuzz$$i.xdr; \
	done

fuzz: fuzz-testcases iotchain-core
	mkdir -p fuzz-findings
	afl-fuzz -m 8000 -t 250 -i fuzz-testcases -o fuzz-findings \
	    ./iotchain-core fuzz @@

fuzz-clean: always
	rm -Rf fuzz-testcases fuzz-findings

distclean-local: fuzz-clean
endif # USE_AFL_FUZZ

CLEANFILES = $(BUILT_SOURCES) *~ */*~ iotchain*.log
MAINTAINERCLEANFILES = $(srcdir)/Makefile.in $(srcdir)/*~ $(srcdir)/*/*~

EXTRA_DIST = $(SRC_X_FILES) test/selftest-nopg test/selftest-pg
