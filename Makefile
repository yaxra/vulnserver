CC = gcc
ASM = nasm
CFLAGS = -m32 -Wall
LDFLAGS = -lws2_32 -shared -Wl,--image-base=0x10000000
ASMFLAGS = -f win32
DLL_NAME = serverdll.dll
SERVER_EXE = vulnserver.exe

all: $(DLL_NAME) $(SERVER_EXE)

jumpesp.obj: jumpesp.asm
	$(ASM) $(ASMFLAGS) $< -o $@

$(DLL_NAME): jumpesp.obj serverdll.c
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

$(SERVER_EXE): vulnserver.c
	$(CC) $(CFLAGS) $< -o $@ -lws2_32

clean:
	del *.obj 2> nul || true

.PHONY: all clean