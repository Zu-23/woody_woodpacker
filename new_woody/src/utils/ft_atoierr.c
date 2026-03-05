#include "../../woody.h"
int ft_atoierr(const char *str, uint64_t *out_key) {
    uint64_t result = 0;

    if (!str || *str == '\0') {
        return 0;
    }

    while (*str) {
        if (*str >= '0' && *str <= '9') {
            result = (result * 10) + (*str - '0');
        } else {
            return 0;
        }
        str++;
    }
    *out_key = result;
    return 1;
}