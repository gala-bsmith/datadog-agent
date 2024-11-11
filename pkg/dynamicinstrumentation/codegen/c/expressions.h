// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

#ifndef DI_EXPRESIONS_H
#define DI_EXPRESIONS_H

static __always_inline int read_register(struct expression_context context, __u64 reg, __u64 element_size)
{
    __u64 valueHolder = 0;
    bpf_probe_read(&valueHolder,  element_size, &context.ctx->DWARF_REGISTER(reg));
    bpf_map_push_elem(&param_stack, &valueHolder, 0);
    return 0;
}

static __always_inline int read_stack(struct expression_context context, size_t stack_offset, __u32 element_size)
{
    __u64 valueHolder = 0;
    bpf_probe_read(&valueHolder, element_size, &context.ctx->DWARF_STACK_REGISTER+stack_offset);
    bpf_map_push_elem(&param_stack, &valueHolder, 0);
    return 0;
}

static __always_inline int read_register_value_to_output(struct expression_context context, __u64 reg, __u64 element_size)
{
    bpf_probe_read(&context.event->output[*(context.output_offset)], element_size, &context.ctx->DWARF_REGISTER(reg));
    *(context.output_offset) += element_size;
    return 0;
}

static __always_inline int read_stack_value_to_output(struct expression_context context, __u64 stack_offset, __u64 element_size)
{
    bpf_probe_read(&context.event->output[*(context.output_offset)], element_size, &context.ctx->DWARF_STACK_REGISTER+stack_offset);
    *(context.output_offset) += element_size;
    return 0;
}

static __always_inline int pop(struct expression_context context, __u64 num_elements, __u64 element_size)
{
    __u64 valueHolder;
    int i;
    for(i = 0; i < num_elements; i++) {
        bpf_map_pop_elem(&param_stack, &valueHolder);
        bpf_probe_read(&context.event->output[*(context.output_offset)+i], element_size, &valueHolder);
        *(context.output_offset) += element_size;
    }
    return 0;
}

#endif