ARCHS     = arm64
SDK       = $(shell xcrun --sdk iphoneos --show-sdk-path)
MIN_IOS   = 14.0
CC        = $(shell xcrun --sdk iphoneos -f clang)

CFLAGS    = -arch $(ARCHS) \
            -isysroot $(SDK) \
            -miphoneos-version-min=$(MIN_IOS) \
            -O2 -fvisibility=hidden \
            -fobjc-arc

LDFLAGS   = -arch $(ARCHS) \
            -isysroot $(SDK) \
            -miphoneos-version-min=$(MIN_IOS) \
            -shared \
            -framework Foundation \
            -framework Security

TARGET    = sf2_moves_hook.dylib
SRCS      = sf2_moves_hook.m fishhook.c

all: $(TARGET)

$(TARGET): $(SRCS) fishhook.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS)
	@echo "Built: $@"

clean:
	rm -f $(TARGET)
