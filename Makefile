KEY_BASE64=<insert base64 key here>
GPP_FLAGS=-m32 -DPRIVATE_SHARED_KEY_BASE64="\"$(KEY_BASE64)\"" -I/usr/include/crypto++ -lcrypto++ -lpthread

.PHONY: all
all: atm bank proxy

%: %.cpp protocol.h
	g++ $< $(GPP_FLAGS) -o $@
