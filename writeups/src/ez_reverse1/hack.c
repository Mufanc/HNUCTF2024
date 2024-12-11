#define getchar getchar_orig

#include <stdio.h>
#include <stdint.h>

#undef getchar

void getchar() {
    uintptr_t return_address = (uintptr_t) __builtin_return_address(0);
    ((void (*)())(return_address + 0x001011b9 - 0x001010bd))();
}
