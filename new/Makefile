NAME = woody_woodpacker

COMPILER = clang
FLAGS = -Wall -Wextra -Werror
SRC_C = main.c #algorithm.c 

OBJC = $(SRC_C:.c=.o)
BONUS_OBJ = $(BONUS_SRC_C:_bonus.c=_bonus.o)

all: $(NAME)

$(NAME): $(OBJC)
	$(COMPILER) $(FLAGS) $(OBJC) -o $(NAME)

%.o: %.c tools.h
	$(COMPILER) $(FLAGS) -c $< -o $@

%_bonus.o: %_bonus.c tools.h
	$(COMPILER) $(FLAGS) -c $< -o $@

bonus: $(BONUS_OBJ)
	$(COMPILER) $(FLAGS) $(BONUS_OBJ) -o $(NAME)

clean:
	rm -rf $(OBJC) $(BOBJC)

fclean: clean
	rm -rf $(NAME)

re: fclean all