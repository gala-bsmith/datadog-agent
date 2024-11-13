// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

#ifndef DI_EXPRESIONS_H
#define DI_EXPRESIONS_H

static __always_inline int read_register(struct expression_context context, __u64 reg, __u32 element_size)
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

static __always_inline int read_register_value_to_output(struct expression_context context, __u64 reg, __u32 element_size)
{
    bpf_probe_read(&context.event->output[*(context.output_offset)], element_size, &context.ctx->DWARF_REGISTER(reg));
    *context.output_offset += element_size;
    return 0;
}

static __always_inline int read_stack_value_to_output(struct expression_context context, __u64 stack_offset, __u32 element_size)
{
    bpf_probe_read(&context.event->output[*(context.output_offset)], element_size, &context.ctx->DWARF_STACK_REGISTER+stack_offset);
    *context.output_offset += element_size;
    return 0;
}

static __always_inline int pop(struct expression_context context, __u64 num_elements, __u32 element_size)
{
    __u64 valueHolder;
    int i;
    for(i = 0; i < num_elements; i++) {
        bpf_map_pop_elem(&param_stack, &valueHolder);
        bpf_probe_read(&context.event->output[*(context.output_offset)+i], element_size, &valueHolder);
        *context.output_offset += element_size;
    }
    return 0;
}

static __always_inline int dereference(struct expression_context context, __u32 element_size)
{
    __u64 addressHolder = 0;
    bpf_map_pop_elem(&param_stack, &addressHolder);

    __u64 valueHolder = 0;
    bpf_probe_read(&valueHolder, element_size, (void*)addressHolder);

    __u64 mask = (element_size == 8) ? ~0ULL : (1ULL << (8 * element_size)) - 1;
    __u64 encodedValueHolder = valueHolder & mask;

    bpf_map_push_elem(&param_stack, &encodedValueHolder, 0);
    return 0;
}

static __always_inline int dereference_to_output(struct expression_context context, __u32 element_size)
{
    __u64 addressHolder = 0;
    bpf_map_pop_elem(&param_stack, &addressHolder);

    __u64 valueHolder = 0;
    bpf_probe_read(&valueHolder, element_size, (void*)addressHolder);

    __u64 mask = (element_size == 8) ? ~0ULL : (1ULL << (8 * element_size)) - 1;
    __u64 encodedValueHolder = valueHolder & mask;

    bpf_probe_read(&context.event->output[*(context.output_offset)], element_size, &encodedValueHolder);
    *context.output_offset += element_size;
    return 0;
}

static __always_inline int dereference_large(struct expression_context context, __u32 element_size, __u8 num_chunks)
{
    __u64 addressHolder = 0;
    bpf_map_pop_elem(&param_stack, &addressHolder);

    int i;
    __u32 chunk_size;
    for (i = 0; i < num_chunks; i++) {
        chunk_size = (i == num_chunks - 1 && element_size % 8 != 0) ? (element_size % 8) : 8;
        bpf_probe_read(&context.temp_storage[i], element_size, (void*)(addressHolder + (i * 8)));
    }

    // Mask the last chunk if element_size is not a multiple of 8
    if (element_size % 8 != 0) {
        __u64 mask = (1ULL << (8 * (element_size % 8))) - 1;
        context.temp_storage[num_chunks - 1] &= mask;
    }

    for (int i = 0; i < num_chunks; i++) {
        bpf_map_push_elem(&param_stack, &context.temp_storage[i], 0);
    }

    // zero out shared array
    bpf_probe_read(context.temp_storage, element_size*num_chunks, context.zero_string);
    return 0;
}

static __always_inline int dereference_large_to_output(struct expression_context context, __u32 element_size)
{
    __u64 addressHolder = 0;
    bpf_map_pop_elem(&param_stack, &addressHolder);
    bpf_probe_read(&context.event->output[*(context.output_offset)], element_size, (void*)(addressHolder));
    *context.output_offset += element_size;
    return 0;
}

static __always_inline int apply_offset(struct expression_context context, size_t offset)
{
    __u64 addressHolder = 0;
    bpf_map_pop_elem(&param_stack, &addressHolder);
    addressHolder += offset;
    bpf_map_push_elem(&param_stack, &addressHolder, 0);
    return 0;
}

static __always_inline int dereference_dynamic(struct expression_context context, __u32 bytes_limit, __u8 num_chunks, __u32 element_size)
{
    __u64 lengthToRead = 0;
    bpf_map_pop_elem(&param_stack, &lengthToRead);

    __u64 addressHolder = 0;
    bpf_map_pop_elem(&param_stack, &addressHolder);

    int i;
    __u32 chunk_size;
    for (i = 0; i < num_chunks; i++) {
        chunk_size = (i == num_chunks - 1 && bytes_limit % 8 != 0) ? (bytes_limit % 8) : 8;
        bpf_probe_read(&context.temp_storage[i], chunk_size, (void*)(addressHolder + (i * 8)));
    }

    for (i = 0; i < num_chunks; i++) {
        bpf_probe_read(&context.event->output[*(context.output_offset)], 8, &context.temp_storage[i]);
        *context.output_offset += 8;
    }
    return 0;
}

static __always_inline int dereference_dynamic_to_output(struct expression_context context, __u32 bytes_limit)
{
    __u64 lengthToRead = 0;
    bpf_map_pop_elem(&param_stack, &lengthToRead);

    __u64 addressHolder = 0;
    bpf_map_pop_elem(&param_stack, &addressHolder);

    __u16 collection_size;
    collection_size = lengthToRead;
    if (collection_size > bytes_limit) {
        collection_size = bytes_limit;
    }

    bpf_probe_read(&context.event->output[*(context.output_offset)], collection_size, (void*)addressHolder);
    *context.output_offset += collection_size;
    return 0;
}

static __always_inline int set_global_limit(struct expression_context context, __u16 limit)
{
    // Read the 2 byte length from top of the stack, then set collectionLimit to the minimum of the two
    __u64 length;
    bpf_map_pop_elem(&param_stack, &length);

    *context.limit = (__u16)length;
    if (*context.limit > limit) {
        *context.limit = limit;
    }
    return 0;
}

static __always_inline int copy(struct expression_context context)
{
    __u64 holder;
    bpf_map_peek_elem(&param_stack, &holder);
    bpf_map_push_elem(&param_stack, &holder, 0);
    return 0;
}
#endif