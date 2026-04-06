#include "woody.h"

void add_page(t_book *book, int _index, uint64_t _address){
    t_node *node = NULL;
    node = malloc(sizeof(t_node));
    if (!node){
        write(2, "malloc failed to allocated the node\n", 36);
        exit(1);
    }
    node->index = _index;
    node->address = _address;
    node->next = NULL;
    if (!book->nodes){
        book->nodes = node;
    }
    else {
        t_node *tmp = book->nodes;
        while (tmp->next){
            tmp = tmp->next;
        }
        tmp->next = node;
    }
}

t_book *create_book(unsigned char *buffer){
    t_book *book = NULL;
    book = malloc(sizeof(t_book));
    if (!book){
        write(2, "malloc failed\n", 14);
        exit(1);
    }
    book->buffer = buffer;
    book->nodes = NULL;
    return (book);
}
