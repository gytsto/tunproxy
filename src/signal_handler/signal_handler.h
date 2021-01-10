#ifndef __SGINAL_HANDLER_H__
#define __SGINAL_HANDLER_H__

#include <signal.h>

struct signal_handler
{
    int signal;
    sig_t handler;
};

/**
 * @brief initialize signal handler
 * @param arr signal handler array
 * @param arr_size signal handler array size
 * @return 0 on success, -errno on failure
 */
int signal_handler_init(struct signal_handler const *arr, size_t arr_size);

#endif /* __SGINAL_HANDLER_H__ */
