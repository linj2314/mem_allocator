#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>

typedef struct block_header block_header;

typedef struct block_header {
    size_t size;
    block_header * next; // for free list linking
    void * prev; // previous data ptr in contiguous memory
    char alloc; // 0 for unallocated 1 for allocated
    char end; // 1 if block is last in page else 0
} block_header;

#define OVERHEAD sizeof(block_header)
#define PAGE_SIZE 4096

block_header * free_list_head = NULL;

static inline size_t page_align(size_t bytes) {
    return (((bytes) + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1));
}

// pass in data ptr and get header
static inline block_header * get_header(void * ptr) {
    return (block_header *)((char *)(ptr) - OVERHEAD);
}

// pass in data ptr and get next data ptr
static inline void * get_next(void * ptr) {
    return ((char *)(ptr) + get_header(ptr)->size + OVERHEAD);
}

void append_free_list(block_header * bh) {
    bh->next = free_list_head;
    free_list_head = bh;
}

void remove_free_list(block_header * bh) {
    if (bh == free_list_head) {
        free_list_head = free_list_head->next;
        return;
    }
    block_header * traverse = free_list_head;
    while (traverse->next) {
        if (traverse->next == bh) {
            traverse->next == traverse->next->next;
            return;
        }
    }
}

void * alloc_mem(size_t bytes) {
    if (!bytes)
        return NULL;
    size_t new_bytes = bytes + OVERHEAD;
    void * ptr = NULL;
    block_header * traverse = free_list_head;

    while (traverse) {
        // traverse free list and look for unallocated block that is large enough
        if (traverse->size >= bytes) {
            ptr = traverse;
            remove_free_list(traverse);
            break;
        }
        traverse = traverse->next;
    }

    if (!ptr) {
        ptr = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ptr == MAP_FAILED) {
            printf("Not enough memory left for allocation\n");
            exit(1);
        }
        ((block_header *)ptr)->size = page_align(new_bytes) - OVERHEAD;
        ((block_header *)ptr)->prev = NULL;
    }

    size_t left_over = ((block_header *)ptr)->size - bytes;

    // set header
    ((block_header *)ptr)->alloc = 1;
    ((block_header *)ptr)->size = bytes;
    ((block_header *)ptr)->end = 0;

    // increment ptr to actual data
    ptr = ((char *)(ptr) + OVERHEAD);

    // check if can truncate (enough space left for at least one more header and byte)
    if (left_over > OVERHEAD) {
        block_header * next_header = get_header(get_next(ptr));

        next_header->alloc = 0;
        next_header->size = left_over - OVERHEAD;
        next_header->prev = ptr;
        append_free_list(next_header);
    } else {
        get_header(ptr)->end = 1;
    }

    return ptr;
}

void free_mem(void * ptr) {
    // append_free_list(get_header(ptr));
    block_header * header = get_header(ptr);
    char prev_alloc = 1;
    char next_alloc = 1;

    if (header->prev) {
        block_header * prev_block = get_header(header->prev);
        prev_alloc = prev_block->alloc;
    }

    if (!header->end) {
        block_header * next_block = (char *)header + OVERHEAD + header->size;
        next_alloc = next_block->alloc;
    }

    // coalescing
    if (!prev_alloc && !next_alloc) {

    } else if (!prev_alloc && next_alloc) {

    } else if (prev_alloc && !next_alloc) {

    } else {
        
    }
}

int main() {
    void * test = alloc_mem(4096 - OVERHEAD);
    block_header * header = get_header(test);
    // free_mem(test);
    void * test2 = alloc_mem(10);
    block_header * header2 = get_header(test2);
    return 0;
}