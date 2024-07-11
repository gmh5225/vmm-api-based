#include <Windows.h>
#include <stdio.h>

#include "leechcore.h"
#include "vmmdll.h"

#pragma comment(lib, ".\\libs\\leechcore")
#pragma comment(lib, ".\\libs\\vmm")

int main() 
{
    VMM_HANDLE hVMM = NULL;
    BOOL result;

    printf("CALL:    VMMDLL_Initialize\n");
    LPCSTR args[] = { (LPSTR)"",(LPSTR)"-device", (LPSTR)"FPGA",(LPSTR)"-norefresh" };
    hVMM = VMMDLL_Initialize(3, args);

    if (hVMM) {
        printf("SUCCESS: VMMDLL_Initialize\n");
    }
    else {
        printf("FAIL:    VMMDLL_Initialize\n");
        return 1;
    }

    ULONG64 qwID, qwVersionMajor, qwVersionMinor;
    printf("CALL:    VMMDLL_ConfigGet\n");
    result =
        VMMDLL_ConfigGet(hVMM, LC_OPT_FPGA_FPGA_ID, &qwID) &&
        VMMDLL_ConfigGet(hVMM, LC_OPT_FPGA_VERSION_MAJOR, &qwVersionMajor) &&
        VMMDLL_ConfigGet(hVMM, LC_OPT_FPGA_VERSION_MINOR, &qwVersionMinor);
    if (result) {
        printf("SUCCESS: VMMDLL_ConfigGet\n");
        printf("         ID = %lli\n", qwID);
        printf("         VERSION = %lli.%lli\n", qwVersionMajor, qwVersionMinor);
    }
    else {
        printf("FAIL:    VMMDLL_ConfigGet\n");
        return 1;
    }

	return 0;
}