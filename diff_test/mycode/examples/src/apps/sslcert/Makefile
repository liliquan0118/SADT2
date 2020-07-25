
#
# General
#
#
CC=../../../../../../my_afl/afl-clang
CXX=../../../../../../my_afl/afl-clang++

# CC=clang-3.9
# CXX=clang++-3.9
# Directories
SRC_DIR=../../../src/libs
LIBS_DIR=../../../builds/libs

CERT_DIR=certs
OUT_DIR=out
CORPUS_DIR=corpus_dir
BIG_CORPUS=~/Desktop/corpus
SMALL_CORPUS=corpus_dir
LIBDIR=lib

# LibFuzzer suffix
SUFFIX=_lf

# List of SSL libraries
OPENSSL=$(LIBS_DIR)/openssl$(SUFFIX)
BORINGSSL=$(LIBS_DIR)/boringssl$(SUFFIX)
LIBRESSL=$(LIBS_DIR)/libressl$(SUFFIX)
MBEDTLS=$(LIBS_DIR)/mbedtls$(SUFFIX)
GNUTLS=$(LIBS_DIR)/gnutls$(SUFFIX)
WOLFSSL=$(LIBS_DIR)/wolfssl$(SUFFIX)
NSS=$(LIBS_DIR)/nss$(SUFFIX)

#
#
# Configuration
#
#

# All possible libs: do not remove from this list, just set the appropriate
# USE_LIB_XXX flag, if you want to include this lib in the build
ALL_LIBS =openssl nss wolfssl mbedtls gnutls libressl 
# ALL_LIBS = openssl nss wolfssl mbedtls gnutls libressl boringssl
USE_LIB_OPENSSL=1
# CONFIG: Select libraries to include
# USE_LIB_BORINGSSL=1
USE_LIB_LIBRESSL=1

USE_LIB_GNUTLS=1
USE_LIB_MBEDTLS=1
USE_LIB_WOLFSSL=1
USE_LIB_NSS=1
# populate based on selection above
LIBS =
CONFIG_USE_LIBS =

LIBS=$(foreach l, \
	 $(ALL_LIBS), \
	 $(if $(filter 1,$(USE_LIB_$(shell echo $l | tr a-z A-Z))),$l))

CONFIG_USE_LIBS=$(foreach l, \
				$(ALL_LIBS), \
				$(if $(filter 1,$(USE_LIB_$(shell echo $l | tr a-z A-Z))),\
				-DCONFIG_USE_$(shell echo $l | tr a-z A-Z)))

# CONFIG: Indicate if we are compiling with the main() function for testing
# (Do not set when compiling with libFuzzer)
DBG_MAIN=0
ifeq ($(DBG_MAIN), 1)
CONFIG_DBG_MAIN=-DCONFIG_DBG_MAIN
endif

CONFIG_USE_LF=-DCONFIG_USE_LF

# this cannot be passed at runtime for the tests
# because they are created dynamically
USE_DER=0
ifeq ($(USE_DER), 1)
CONFIG_USE_DER=-DCONFIG_USE_DER
CA_FORMAT=der
BIN_SUFFIX=.der
else
CONFIG_USE_DER=-DCONFIG_USE_PEM
CA_FORMAT=pem
BIN_SUFFIX=.pem
endif

# CONFIG: Enable debugging logs
DBG_LOG=0
ifeq ($(DBG_LOG), 1)

CONFIG_DEBUG=-DCONFIG_DEBUG
ifeq ($(USE_DER), 1)
BIN_SUFFIX=.der.dbg
else
BIN_SUFFIX=.pem.dbg
endif
else
BIN_SUFFIX=.$(CA_FORMAT)
endif

SUM=0
ifeq ($(SUM), 1)
CONFIG_DEBUG=-DCONFIG_SUMMARY
endif

OPTIONS=$(CONFIG_DBG_MAIN) $(CONFIG_USE_DER) $(CONFIG_DEBUG)
DBGFLAGS=-g -ggdb3
CFLAGS=-O0 -Wall $(DBGFLAGS) $(OPTIONS) -lcrypto -lpthread -pthread 
CFLAGS_SHARED_O=-fPIC -fvisibility=hidden
CFLAGS_SHARED_LIB=$(CFLAGS_SHARED_O) -rdynamic -shared
# COV_MAIN_FLAGS=-fsanitize=address -fsanitize-recover=undefined,integer
# COV_FULL_FLAGS=-fsanitize-coverage=edge,indirect-calls,8bit-counters

#
#
# Flags
#
#
LDFLAG= -g -O0
INC_BORINGSSL= -I$(BORINGSSL)/include
LD_BORINGSSL=-L$(BORINGSSL)/build/crypto -L$(BORINGSSL)/crypto -lcrypto -pthread \
			 -Wl,-static -lcrypto -Wl,-Bdynamic $(LDFLAG)

INC_OPENSSL= -I$(OPENSSL)/include
LD_OPENSSL= -L$(OPENSSL)/lib -rpath $(OPENSSL)/lib -lcrypto -ldl $(LDFLAG)

INC_LIBRESSL= -I$(LIBRESSL)/include
LD_LIBRESSL= -L$(LIBRESSL)/lib  -lcrypto -Wl,-static -lcrypto -Wl,-Bdynamic 

INC_GNUTLS= -I $(GNUTLS)/include
LD_GNUTLS= -L $(GNUTLS)/lib -rpath $(GNUTLS)/lib -lcrypto -lpthread -lgnutls -Wl,-Bdynamic -ldl $(LDFLAG)

INC_MBEDTLS= -I $(MBEDTLS)/include
LD_MBEDTLS= -L $(MBEDTLS)/lib -rpath $(MBEDTLS)/lib -lcrypto -lpthread -lmbedtls -lmbedx509 -lmbedcrypto -Wl,-Bdynamic -ldl $(LDFLAG)

INC_WOLFSSL= -I $(WOLFSSL)/include
LD_WOLFSSL= -L $(WOLFSSL)/lib -rpath $(WOLFSSL)/lib -lcrypto -lpthread -lwolfssl  -Wl,-Bdynamic -ldl $(LDFLAG)

INC_NSS= -I$(NSS)/include -I$(NSS)/include/nspr
LD_NSS= -L $(NSS)/lib -rpath $(NSS)/lib -lcrypto  -lnss3 -lnssutil3 -lsoftokn3  -lsmime3 -lssl -lpthread -Wl,-Bdynamic -ldl $(LDFLAG)
LD_MAIN=-ldl -lstdc++ -lpthread
#
#
# Make Rules
#
#
TARGET=diff$(BIN_SUFFIX)

.PHONY:all
all: prelim $(TARGET)

.PHONY:prelim
prelim:
	mkdir -p $(LIBDIR) $(OUT_DIR)

define mk_libs
lib$1_$(CA_FORMAT).so: $1.cpp
	$(CXX) $(CFLAGS) $(CFLAGS_SHARED_O) $(INC_$(shell echo $1 | tr a-z A-Z)) \
		 -c -o $1.o $1.cpp

	$(CXX) $(CFLAGS) $(CFLAGS_SHARED_LIB) \
			-o lib$1_$(CA_FORMAT).so $1.o $(LD_$(shell echo $1 | tr a-z A-Z))
	mv lib$1_$(CA_FORMAT).so $(LIBDIR)
endef

$(foreach l, $(LIBS), \
  $(eval $(call mk_libs,$(l))) \
)

define mk_libs2
lib$1_parse_$(CA_FORMAT).so: $1_parse.cpp
	$(CXX) $(CFLAGS) $(CFLAGS_SHARED_O) $(INC_$(shell echo $1 | tr a-z A-Z)) \
		 -c -o $1_parse.o $1_parse.cpp

	$(CXX) $(CFLAGS) $(CFLAGS_SHARED_LIB) \
			-o lib$1_parse_$(CA_FORMAT).so $1_parse.o $(LD_$(shell echo $1 | tr a-z A-Z))
	mv lib$1_parse_$(CA_FORMAT).so $(LIBDIR)
endef
$(foreach l, $(LIBS), \
  $(eval $(call mk_libs2,$(l))) \
)
afl: afl_target.cpp $(foreach l, $(LIBS), lib$(l)_$(CA_FORMAT).so)
	$(CXX) $(CFLAGS)  \
			$(foreach l, $(LIBS), $(INC_$(shell echo $(l) | tr a-z A-Z)))  \
			$(CONFIG_USE_LIBS) $(LDFLAG) $< -o $@ $(LD_MAIN)

afl2: afl_target2.cpp $(foreach l, $(LIBS), lib$(l)_$(CA_FORMAT).so)
	$(CXX) $(CFLAGS)  \
			$(foreach l, $(LIBS), $(INC_$(shell echo $(l) | tr a-z A-Z)))  \
			$(CONFIG_USE_LIBS) $(LDFLAG) $< -o $@ $(LD_MAIN)
#
#
# Test rules
#
#

TEST_CERT=test_cert.$(CA_FORMAT)
TEST_COMMON=main_test.cpp
# mbedTLS does not accept 1024!
KEY_SZ=2048

.PHONY: mk_all_tests
mk_all_tests: $(foreach l, $(LIBS), test_$(l))

.PHONY: run_all_tests
run_all_tests: $(foreach l, $(LIBS), run_test_$(l))

define mk_tests
test_$1:
	$(CXX) $(COV_MAIN_FLAGS) -lpthread  -DCONFIG_TEST_$(shell echo $1 | tr a-z A-Z) \
	-DCONFIG_DBG_MAIN $(CFLAGS) $(INC_$(shell echo $1 | tr a-z A-Z)) \
	$(TEST_COMMON) $1.cpp -o test_$1$(BIN_SUFFIX) \
	$(LD_$(shell echo $1 | tr a-z A-Z))
endef

$(foreach l, $(LIBS), \
  $(eval $(call mk_tests,$(l))) \
)

define mk_run_tests
run_test_$1:
	ASAN_OPTIONS=halt_on_error=0 ./test_$1$(BIN_SUFFIX) \
				 $(CERT_DIR)/$(TEST_CERT)
endef

$(foreach l, $(LIBS), \
  $(eval $(call mk_run_tests,$(l))) \
)

