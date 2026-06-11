NAME = woody_woodpacker

COMPILER = clang
FLAGS = -Wall -Wextra -Werror
SRC_C = main.c
ASSAMBLER = nasm
ASSAMBLER_FLAGS = -f bin
ALG = encryption.s
ALGO = encryption.o

OBJC = $(SRC_C:.c=.o)

BONUS_OBJ = $(BONUS_SRC_C:_bonus.c=_bonus.o)

all: $(NAME)

$(NAME): $(OBJC)
	$(COMPILER) $(FLAGS) $(OBJC)  -o $(NAME)
	$(ASSAMBLER) $(ASSAMBLER_FLAGS) stub64.s -o stub64.bin

%.o: %.c woody.h
	$(COMPILER) $(FLAGS) -c $< -o $@

clean:
	rm -rf $(OBJC) $(BOBJC)

woody:
	rm -rf woody

fclean: clean
	rm -rf $(NAME) stub64.bin stub32.bin woody

re: fclean all