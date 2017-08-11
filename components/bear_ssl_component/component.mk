
COMPONENT_ADD_INCLUDEDIRS := ../bear_ssl/.	\
							../bear_ssl/inc \
							../bear_ssl/src \
							../bear_ssl/tools
							
COMPONENT_SRCDIRS +=	../bear_ssl/src/codec \
						../bear_ssl/src/ec \
						../bear_ssl/src/hash \
						../bear_ssl/src/int \
						../bear_ssl/src/mac \
						../bear_ssl/src/rand \
						../bear_ssl/src/rsa \
						../bear_ssl/src/ssl \
						../bear_ssl/src/symcipher \
						../bear_ssl/src/x509 \
						../bear_ssl/src 
CFLAGS += -DBR_USE_ALT_RAND -DBR_USE_UNIX_TIME