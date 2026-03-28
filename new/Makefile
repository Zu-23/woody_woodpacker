NAME = woody_woodpacker

COMPILER = clang
FLAGS = -Wall -Wextra -Werror
SRC_C = main.c 
ASSAMBLER = nasm
ASSAMBLER_FLAGS = -f bin

OBJC = $(SRC_C:.c=.o)
BONUS_OBJ = $(BONUS_SRC_C:_bonus.c=_bonus.o)

all: $(NAME)

$(NAME): $(OBJC)
	$(COMPILER) $(FLAGS) $(OBJC) -o $(NAME)

%.o: %.c woody.h
	$(COMPILER) $(FLAGS) -c $< -o $@

%_bonus.o: %_bonus.c tools.h
	$(COMPILER) $(FLAGS) -c $< -o $@

bonus: $(BONUS_OBJ)
	$(COMPILER) $(FLAGS) $(BONUS_OBJ) -o $(NAME)

stub64:
	$(ASSAMBLER) $(ASSAMBLER_FLAGS) stub64.s -o stub64.bin
	xxd -i stub64.bin

clean:
	rm -rf $(OBJC) $(BOBJC)

fclean: clean
	rm -rf $(NAME) stub64.bin stub32.bin

re: fclean all