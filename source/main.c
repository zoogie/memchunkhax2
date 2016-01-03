#include <3ds.h>

#include <stdio.h>

#include "memchunkhax2.h"

int main(int argc, char **argv) {
    Handle amHandle = 0;
    Result res;
    u8 success;

    gfxInitDefault();
    consoleInit(GFX_TOP, NULL);

    // This one should fail
    res = srvGetServiceHandleDirect(&amHandle, "am:u");
    printf("am:u init1 result/handle: res=%lu handle=%lu\n", res, amHandle);
    if(amHandle) {
        svcCloseHandle(amHandle);
    }

    // Run the exploit
    success = execute_memchunkhax2();
    printf("Exploit returned: %s\n", success ? "Success!" : "Failure.");

    // This one hopefully won't
    res = srvGetServiceHandleDirect(&amHandle, "am:u");
    printf("am:u init2 result/handle: res=%lu handle=%lu\n", res, amHandle);
    if(amHandle) {
        svcCloseHandle(amHandle);
    }

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
