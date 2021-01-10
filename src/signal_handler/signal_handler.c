#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "signal_handler.h"

static struct signal_handler const *_signal_array;
static size_t _signal_array_size;

int signal_handler_init(struct signal_handler const *arr, size_t arr_size)
{
    if (!arr || !arr_size) {
        errno = -EINVAL;
        return -1;
    }

    _signal_array = arr;
    _signal_array_size = arr_size;

    for (int i = 0; i < _signal_array_size; i++) {
        signal(_signal_array[i].signal, _signal_array[i].handler);
    }

    return 0;
}
