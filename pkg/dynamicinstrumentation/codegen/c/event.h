#ifndef DI_EVENT_H
#define DI_EVENT_H

#include "ktypes.h"

struct event {
    struct base_event base;
    char output[PARAM_BUFFER_SIZE];
};

struct expression_context {
    int *output_offset;
    struct pt_regs *ctx;
    struct event *event;
};

#endif
