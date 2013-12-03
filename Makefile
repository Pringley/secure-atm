CRYPTOPP_INC?=/usr/include/crypto++
CRYPTOPP_LIB_PATH?=/usr/lib
KEY_BASE64?=dummykey
GPP_FLAGS=-m32 -DPRIVATE_SHARED_KEY_BASE64="\"$(KEY_BASE64)\"" -I$(CRYPTOPP_INC) -L$(CRYPTOPP_LIB_PATH) -lcrypto++ -lpthread

.PHONY: all
all: atm bank proxy

%: %.cpp protocol.h
	g++ $< $(GPP_FLAGS) -o $@
