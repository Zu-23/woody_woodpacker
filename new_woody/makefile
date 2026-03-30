NAME =          woody_woodpacker
CC =            gcc
CFLAGS =        -Wall -Wextra -Werror

MINGW_CC =      x86_64-w64-mingw32-gcc
MINGW_LD =      x86_64-w64-mingw32-ld
MINGW_OBJCOPY = x86_64-w64-mingw32-objcopy
MINGW_CFLAGS =  -O0 -fno-ident -fno-stack-protector -fno-asynchronous-unwind-tables -fPIC -nostdlib

NASM =          nasm
NASM_FLAGS =    -f bin # Default for Linux ELF stubs

SRC_DIR =       src
UTIL_DIR =      src/utils
STUB_DIR =      stubs

STUB_SRC =      $(wildcard $(STUB_DIR)/*.s)
STUB_BIN =      $(STUB_SRC:.s=.bin)

SRC =           main.c $(wildcard $(SRC_DIR)/*.c) $(wildcard $(UTIL_DIR)/*.c)
OBJ =           $(SRC:.c=.o)

all: $(NAME) stub

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(NAME)

%.o: %.c woody.h
	$(CC) $(CFLAGS) -c $< -o $@

stub: $(STUB_BIN)

$(STUB_DIR)/stub_pe64.bin: $(STUB_DIR)/stub_pe64.s $(STUB_DIR)/print.c
	@echo "Building Windows Mixed Payload..."
	$(NASM) -f win64 $< -o $(STUB_DIR)/stub_pe64.o
	$(MINGW_CC) $(MINGW_CFLAGS) -c $(STUB_DIR)/print.c -o $(STUB_DIR)/print.o
	$(MINGW_LD) $(STUB_DIR)/stub_pe64.o $(STUB_DIR)/print.o -o $(STUB_DIR)/combined.exe -e _start
	$(MINGW_OBJCOPY) -O binary -j .text $(STUB_DIR)/combined.exe $@
	@rm -f $(STUB_DIR)/stub_pe64.o $(STUB_DIR)/print.o $(STUB_DIR)/combined.exe
	@echo "Windows payload compiled successfully!"

$(STUB_DIR)/%.bin: $(STUB_DIR)/%.s
	$(NASM) $(NASM_FLAGS) $< -o $@

clean:
	rm -f $(OBJ) woody stubs/*.bin stubs/*.o stubs/*.exe

fclean: clean
	rm -f $(NAME) woody

re: fclean all

.PHONY: all clean fclean re stub