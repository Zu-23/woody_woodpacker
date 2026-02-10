NAME        = woody_woodpacker
CC          = gcc
CFLAGS      = -Wall -Wextra -Werror

NASM        = nasm
NASM_FLAGS  = -f bin

FUNC_DIR    = funcs
SRC         = new_woody.c $(wildcard $(FUNC_DIR)/*.c)
OBJ         = $(SRC:.c=.o)

STUB_SRC    = stub.s
STUB_BIN    = stub.bin


all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(NAME)

%.o: %.c woody.h
	$(CC) $(CFLAGS) -c $< -o $@

stub: $(STUB_BIN)
	rm target
	gcc hello.c -o target

$(STUB_BIN): $(STUB_SRC)
	$(NASM) $(NASM_FLAGS) $(STUB_SRC) -o $(STUB_BIN)

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(NAME) $(STUB_BIN) woody

re: fclean all stub

.PHONY: all clean fclean re stub
