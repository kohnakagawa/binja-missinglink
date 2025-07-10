#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

// Function pointer type for our indirect calls
typedef void (*func_ptr_t)(void);

// Function pointer table for intra-module indirect calls
struct func_table {
    func_ptr_t func1;
    func_ptr_t func2;
};

// Functions that will be called indirectly within the module
void module_func1(void) {
    printf("Called module_func1\n");
}

void module_func2(void) {
    printf("Called module_func2\n");
}

// Function to demonstrate intra-module indirect call
void test_intra_module_call(struct func_table* table, int index) {
    func_ptr_t func = (index == 0) ? table->func1 : table->func2;
    func();  // Indirect call within the module
}

// Function to demonstrate inter-module indirect call
void test_inter_module_call(void* handle, const char* func_name) {
    func_ptr_t func = (func_ptr_t)dlsym(handle, func_name);
    if (func) {
        func();  // Indirect call to another module
    }
}

int main(void) {
    // Test intra-module indirect calls
    struct func_table table = {
        .func1 = module_func1,
        .func2 = module_func2
    };

    printf("Testing intra-module indirect calls:\n");
    test_intra_module_call(&table, 0);  // Will call module_func1
    test_intra_module_call(&table, 1);  // Will call module_func2

    // Test inter-module indirect calls
    void* handle = dlopen("./libtest_module.dylib", RTLD_LAZY);
    if (handle) {
        printf("\nTesting inter-module indirect calls:\n");
        test_inter_module_call(handle, "external_func1");
        test_inter_module_call(handle, "external_func2");
        dlclose(handle);
    }

    return 0;
} 