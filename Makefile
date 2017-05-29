#
# This is a project Makefile. It is assumed the directory this Makefile resides in is a
# project subdirectory.
#

PROJECT_NAME := alexa

COMPONENT_ADD_INCLUDEDIRS := components/include

include $(IDF_PATH)/make/project.mk

# Copy some defaults into the sdkconfig by default
# so BT stack is enabled
sdkconfig: sdkconfig.defaults
	$(Q) cp $< $@

menuconfig: sdkconfig
defconfig: sdkconfig

# debug flags:
# mbedTLS: -DMBEDTLS_DEBUG_C 
# nghttp2: -DDEBUGBUILD
# multipart_parser: -DDEBUG_MULTIPART

# CFLAGS += -DMBEDTLS_SSL_SRV_RESPECT_CLIENT_PREFERENCE -DMBEDTLS_DEBUG_C -DDEBUGBUILD
