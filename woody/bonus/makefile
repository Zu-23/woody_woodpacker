NAME        = woody_woodpacker
CC          = gcc
CFLAGS      = -Wall -Wextra -Werror

NASM        = nasm
NASM_FLAGS  = -f bin

FUNC_DIR    = funcs
SRC         = main.c $(wildcard $(FUNC_DIR)/*.c)
OBJ         = $(SRC:.c=.o)

STUB_SRC    = stub.s
STUB_BIN    = stub.bin


all: $(NAME) target stub clean

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(NAME)

%.o: %.c woody.h
	$(CC) $(CFLAGS) -c $< -o $@

stub: $(STUB_BIN)

$(STUB_BIN): $(STUB_SRC)
	$(NASM) $(NASM_FLAGS) $(STUB_SRC) -o $(STUB_BIN)

target:
	$(CC) $(CFLAGS) hello.c -o target


clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(NAME) $(STUB_BIN) woody target

re: fclean all

.PHONY: all clean fclean re stub
