NAME =			woody_woodpacker
CC =			gcc
CFLAGS =		-Wall -Wextra -Werror
NASM =			nasm
NASM_FLAGS =	-f bin
SRC_DIR =		src
UTIL_DIR =		src/utils
STUB_DIR =		stubs
STUB_SRC =		$(wildcard $(STUB_DIR)/*.s)
STUB_BIN =		$(STUB_SRC:.s=.bin)
SRC =			main.c $(wildcard $(SRC_DIR)/*.c) $(wildcard $(UTIL_DIR)/*.c)
OBJ =			$(SRC:.c=.o)

all: $(NAME)  stub

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(NAME)

%.o: %.c woody.h
	$(CC) $(CFLAGS) -c $< -o $@

stub:  $(STUB_BIN)

$(STUB_BIN): $(STUB_SRC)
	$(NASM) $(NASM_FLAGS) $< -o $@

clean:
	rm -f $(OBJ)
fclean: clean
	rm -f $(NAME)	
re: fclean all
.PHONY: all clean fclean re