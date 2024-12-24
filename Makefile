all: mem_allocator

.PHONY: clean mem_allocator mem_allocator_debug

clean:
	rm -f mem_allocator mem_allocator_debug

debug: mem_allocator_debug

mem_allocator:
	gcc mem_allocator.c -o mem_allocator

mem_allocator_debug:
	gcc -O0 -g mem_allocator.c -o mem_allocator_debug