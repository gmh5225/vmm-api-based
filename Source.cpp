#include <Windows.h>
#include <stdio.h>
#include <conio.h>
#include "leechcore.h"
#include "vmmdll.h"

#pragma comment(lib, ".\\libs\\leechcore")
#pragma comment(lib, ".\\libs\\vmm")

LPSTR VadMap_Type(_In_ PVMMDLL_MAP_VADENTRY pVad)
{
    if (pVad->fImage) {
        return (LPSTR)"Image";
    }
    else if (pVad->fFile) {
        return (LPSTR)"File ";
    }
    else if (pVad->fHeap) {
        return (LPSTR)"Heap ";
    }
    else if (pVad->fStack) {
        return (LPSTR)"Stack";
    }
    else if (pVad->fTeb) {
        return (LPSTR)"Teb  ";
    }
    else if (pVad->fPageFile) {
        return (LPSTR)"Pf   ";
    }
    else {
        return (LPSTR)"     ";
    }
}

VOID VadMap_Protection(_In_ PVMMDLL_MAP_VADENTRY pVad, _Out_writes_(6) LPSTR sz)
{
    BYTE vh = (BYTE)pVad->Protection >> 3;
    BYTE vl = (BYTE)pVad->Protection & 7;
    sz[0] = pVad->fPrivateMemory ? 'p' : '-';                                    // PRIVATE MEMORY
    sz[1] = (vh & 2) ? ((vh & 1) ? 'm' : 'g') : ((vh & 1) ? 'n' : '-');         // -/NO_CACHE/GUARD/WRITECOMBINE
    sz[2] = ((vl == 1) || (vl == 3) || (vl == 4) || (vl == 6)) ? 'r' : '-';     // COPY ON WRITE
    sz[3] = (vl & 4) ? 'w' : '-';                                               // WRITE
    sz[4] = (vl & 2) ? 'x' : '-';                                               // EXECUTE
    sz[5] = ((vl == 5) || (vl == 7)) ? 'c' : '-';                               // COPY ON WRITE
    if (sz[1] != '-' && sz[2] == '-' && sz[3] == '-' && sz[4] == '-' && sz[5] == '-') { sz[1] = '-'; }
}

VOID ShowKeyPress()
{
    printf("PRESS ANY KEY TO CONTINUE ...\n");
    Sleep(250);
    _getch();
}

VOID PrintHexAscii(_In_ PBYTE pb, _In_ DWORD cb)
{
    LPSTR sz;
    DWORD szMax = 0;
    VMMDLL_UtilFillHexAscii(pb, cb, 0, NULL, &szMax);
    if (!(sz = (LPSTR)LocalAlloc(0, szMax))) { return; }
    VMMDLL_UtilFillHexAscii(pb, cb, 0, sz, &szMax);
    printf("%s", sz);
    LocalFree(sz);
}

int main() 
{
    ShowKeyPress();
    VMM_HANDLE hVMM = NULL;
    BOOL result;
    BYTE pbPage1[0x1000];
    DWORD dwPID;

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

    ShowKeyPress();

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

    ShowKeyPress();

    // Read physical memory at physical address 0x1000 and display the first
    // 0x100 bytes on-screen.
    printf("------------------------------------------------------------\n");
    printf("# Read from physical memory (0x1000 bytes @ 0x1000).        \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_MemRead\n");
    result = VMMDLL_MemRead(hVMM, -1, 0x1000, pbPage1, 0x1000);
    if (result) {
        printf("SUCCESS: VMMDLL_MemRead\n");
        PrintHexAscii(pbPage1, 0x100);
    }
    else {
        printf("FAIL:    VMMDLL_MemRead\n");
        return 1;
    }

    // Retrieve PID of explorer.exe
    // NB! if multiple explorer.exe exists only one will be returned by this
    // specific function call. Please see .h file for additional information
    // about how to retrieve the complete list of PIDs in the system by using
    // the function PCILeech_VmmProcessListPIDs instead.
    printf("------------------------------------------------------------\n");
    printf("# Get PID from the first 'explorer.exe' process found.      \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_PidGetFromName\n");
    result = VMMDLL_PidGetFromName(hVMM, "explorer.exe", &dwPID);
    if (result) {
        printf("SUCCESS: VMMDLL_PidGetFromName\n");
        printf("         PID = %i\n", dwPID);
    }
    else {
        printf("FAIL:    VMMDLL_PidGetFromName\n");
        return 1;
    }


    // Retrieve additional process information such as: name of the process,
    // PML4 (PageDirectoryBase) PML4-USER (if exists) and Process State.
    printf("------------------------------------------------------------\n");
    printf("# Get Process Information from 'explorer.exe'.              \n");
    ShowKeyPress();
    VMMDLL_PROCESS_INFORMATION ProcessInformation;
    SIZE_T cbProcessInformation = sizeof(VMMDLL_PROCESS_INFORMATION);
    ZeroMemory(&ProcessInformation, sizeof(VMMDLL_PROCESS_INFORMATION));
    ProcessInformation.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
    ProcessInformation.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
    printf("CALL:    VMMDLL_ProcessGetInformation\n");
    result = VMMDLL_ProcessGetInformation(hVMM, dwPID, &ProcessInformation, &cbProcessInformation);
    if (result) {
        printf("SUCCESS: VMMDLL_ProcessGetInformation\n");
        printf("         Name = %s\n", ProcessInformation.szName);
        printf("         PageDirectoryBase = 0x%016llx\n", ProcessInformation.paDTB);
        printf("         PageDirectoryBaseUser = 0x%016llx\n", ProcessInformation.paDTB_UserOpt);
        printf("         ProcessState = 0x%08x\n", ProcessInformation.dwState);
        printf("         PID = 0x%08x\n", ProcessInformation.dwPID);
        printf("         ParentPID = 0x%08x\n", ProcessInformation.dwPPID);
    }
    else {
        printf("FAIL:    VMMDLL_ProcessGetInformation\n");
        return 1;
    }


    // Retrieve process information such as: name of the process, PML4 (DTB),
    // PML4-USER (if exists) and Process State from _all_ processes.
    // Active processes will have ProcessState = 0.
    printf("------------------------------------------------------------\n");
    printf("# Get Process Information from ALL PROCESSES.               \n");
    ShowKeyPress();
    DWORD cProcessInformation = 0;
    PVMMDLL_PROCESS_INFORMATION pProcessInformationEntry, pProcessInformationAll = NULL;
    printf("CALL:    VMMDLL_ProcessGetInformationAll\n");
    result = VMMDLL_ProcessGetInformationAll(hVMM, &pProcessInformationAll, &cProcessInformation);
    if (result) {
        // print results upon success:
        printf("SUCCESS: VMMDLL_ProcessGetInformationAll\n");
        for (int i = 0; i < cProcessInformation; i++) {
            pProcessInformationEntry = &pProcessInformationAll[i];
            printf("         --------------------------------------\n");
            printf("         Name =                  %s\n", pProcessInformationEntry->szName);
            printf("         LongName =              %s\n", pProcessInformationEntry->szNameLong);
            printf("         PageDirectoryBase =     0x%016llx\n", pProcessInformationEntry->paDTB);
            printf("         PageDirectoryBaseUser = 0x%016llx\n", pProcessInformationEntry->paDTB_UserOpt);
            printf("         ProcessState =          0x%08x\n", pProcessInformationEntry->dwState);
            printf("         PID =                   0x%08x\n", pProcessInformationEntry->dwPID);
            printf("         ParentPID =             0x%08x\n", pProcessInformationEntry->dwPPID);
        }
        // free function allocated memory:
        VMMDLL_MemFree(pProcessInformationAll);
    }
    else {
        printf("FAIL:    VMMDLL_ProcessGetInformationAll\n");
        return 1;
    }


    // Retrieve the memory map from the virtual address descriptors (VAD). This
    // function also makes additional parsing to identify modules and tag the
    // memory map with them.
    printf("------------------------------------------------------------\n");
    printf("# Get VAD Memory Map of 'explorer.exe'.                     \n");
    ShowKeyPress();
    CHAR szVadProtection[7] = { 0 };
    PVMMDLL_MAP_VAD pVadMap = NULL;
    PVMMDLL_MAP_VADENTRY pVadMapEntry;
    printf("CALL:    VMMDLL_Map_GetVadU\n");
    result = VMMDLL_Map_GetVadU(hVMM, dwPID, TRUE, &pVadMap);
    if (!result) {
        printf("FAIL:    VMMDLL_Map_GetVadU\n");
        return 1;
    }
    if (pVadMap->dwVersion != VMMDLL_MAP_VAD_VERSION) {
        printf("FAIL:    VMMDLL_Map_GetVadU - BAD VERSION\n");
        VMMDLL_MemFree(pVadMap); pVadMap = NULL;
        return 1;
    }
    {
        printf("SUCCESS: VMMDLL_Map_GetVadU\n");
        printf("         #    ADRESS_RANGE                      KERNEL_ADDR        TYPE  PROT   INFO \n");
        printf("         ============================================================================\n");
        for (int i = 0; i < pVadMap->cMap; i++) {
            pVadMapEntry = &pVadMap->pMap[i];
            VadMap_Protection(pVadMapEntry, szVadProtection);
            printf(
                "         %04x %016llx-%016llx [%016llx] %s %s %s\n",
                i,
                pVadMapEntry->vaStart,
                pVadMapEntry->vaEnd,
                pVadMapEntry->vaVad,
                VadMap_Type(pVadMapEntry),
                szVadProtection,
                pVadMapEntry->uszText
            );
        }
        VMMDLL_MemFree(pVadMap); pVadMap = NULL;
    }


     // Retrieve the list of loaded DLLs from the process. Please note that this
     // list is retrieved by parsing in-process memory structures such as the
     // process environment block (PEB) which may be partly destroyed in some
     // processes due to obfuscation and anti-reversing. If that is the case the
     // memory map may use alternative parsing techniques to list DLLs.
    printf("------------------------------------------------------------\n");
    printf("# Get Module Map of 'explorer.exe'.                         \n");
    ShowKeyPress();
    PVMMDLL_MAP_MODULE pModuleMap = NULL;
    printf("CALL:    VMMDLL_Map_GetModuleU\n");
    result = VMMDLL_Map_GetModuleU(hVMM, dwPID, &pModuleMap, 0);
    if (!result) {
        printf("FAIL:    VMMDLL_Map_GetModuleU #1\n");
        return 1;
    }
    if (pModuleMap->dwVersion != VMMDLL_MAP_MODULE_VERSION) {
        printf("FAIL:    VMMDLL_Map_GetModuleU - BAD VERSION\n");
        VMMDLL_MemFree(pModuleMap); pModuleMap = NULL;
        return 1;
    }
    {
        printf("SUCCESS: VMMDLL_Map_GetModuleU\n");
        printf("         MODULE_NAME                                 BASE             SIZE     ENTRY           PATH\n");
        printf("         ==========================================================================================\n");
        for (int i = 0; i < pModuleMap->cMap; i++) {
            printf(
                "         %-40.40s %s %016llx %08x %016llx %s\n",
                pModuleMap->pMap[i].uszText,
                pModuleMap->pMap[i].fWoW64 ? "32" : "  ",
                pModuleMap->pMap[i].vaBase,
                pModuleMap->pMap[i].cbImageSize,
                pModuleMap->pMap[i].vaEntry,
                pModuleMap->pMap[i].uszFullName
            );
        }
        VMMDLL_MemFree(pModuleMap); pModuleMap = NULL;
    }



    // Retrieve the module of explorer.exe by its name. Note it is also possible
    // to retrieve it by retrieving the complete module map (list) and iterate
    // over it. But if the name of the module is known this is more convenient.
    // This required that the PEB and LDR list in-process haven't been tampered
    // with ...
    printf("------------------------------------------------------------\n");
    printf("# Get module by name 'explorer.exe' in 'explorer.exe'.      \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_Map_GetModuleFromNameU\n");
    PVMMDLL_MAP_MODULEENTRY pModuleEntryExplorer;
    result = VMMDLL_Map_GetModuleFromNameU(hVMM, dwPID, "explorer.exe", &pModuleEntryExplorer, 0);
    if (result) {
        printf("SUCCESS: VMMDLL_Map_GetModuleFromNameU\n");
        printf("         MODULE_NAME                                 BASE             SIZE     ENTRY\n");
        printf("         ======================================================================================\n");
        printf(
            "         %-40.40s %i %016llx %08x %016llx\n",
            "explorer.exe",
            pModuleEntryExplorer->fWoW64 ? 32 : 64,
            pModuleEntryExplorer->vaBase,
            pModuleEntryExplorer->cbImageSize,
            pModuleEntryExplorer->vaEntry
        );
    }
    else {
        printf("FAIL:    VMMDLL_Map_GetModuleFromNameU\n");
        VMMDLL_MemFree(pModuleEntryExplorer); pModuleEntryExplorer = NULL;
        return 1;
    }


    // HANDLES: Retrieve handle information about handles in the explorer.exe
    // process and display on the screen.
    printf("------------------------------------------------------------\n");
    printf("# Get Handle Information of 'explorer.exe'.                 \n");
    ShowKeyPress();
    PVMMDLL_MAP_HANDLE pHandleMap = NULL;
    PVMMDLL_MAP_HANDLEENTRY pHandleMapEntry;
    printf("CALL:    VMMDLL_Map_GetHandleU\n");
    result = VMMDLL_Map_GetHandleU(hVMM, dwPID, &pHandleMap);
    if (!result) {
        printf("FAIL:    VMMDLL_Map_GetHandleU\n");
        return 1;
    }
    if (pHandleMap->dwVersion != VMMDLL_MAP_HANDLE_VERSION) {
        printf("FAIL:    VMMDLL_Map_GetHandleU - BAD VERSION\n");
        VMMDLL_MemFree(pHandleMap); pHandleMap = NULL;
        return 1;
    }
    {
        printf("SUCCESS: VMMDLL_Map_GetHandleU\n");
        printf("         #         HANDLE   PID ADDR_OBJECT      ACCESS TYPE             DESCRIPTION\n");
        printf("         ===========================================================================\n");
        for (int i = 0; i < pHandleMap->cMap; i++) {
            pHandleMapEntry = &pHandleMap->pMap[i];
            printf(
                "         %04x %8x %8x %016llx %6x %-16s %s\n",
                i,
                pHandleMapEntry->dwHandle,
                pHandleMapEntry->dwPID,
                pHandleMapEntry->vaObject,
                pHandleMapEntry->dwGrantedAccess,
                pHandleMapEntry->uszType,
                pHandleMapEntry->uszText
            );
        }
        VMMDLL_MemFree(pHandleMap); pHandleMap = NULL;
    }

    // Retrieve the module of kernel32.dll by its name. Note it is also possible
    // to retrieve it by retrieving the complete module map (list) and iterate
    // over it. But if the name of the module is known this is more convenient.
    // This required that the PEB and LDR list in-process haven't been tampered
    // with ...
    printf("------------------------------------------------------------\n");
    printf("# Get by name 'kernel32.dll' in 'explorer.exe'.             \n");
    ShowKeyPress();
    printf("CALL:    VMMDLL_Map_GetModuleFromNameU\n");
    PVMMDLL_MAP_MODULEENTRY pModuleEntryKernel32;
    result = VMMDLL_Map_GetModuleFromNameU(hVMM, dwPID, "kernel32.dll", &pModuleEntryKernel32, 0);
    if (result) {
        printf("SUCCESS: VMMDLL_Map_GetModuleFromNameU\n");
        printf("         MODULE_NAME                                 BASE             SIZE     ENTRY\n");
        printf("         ======================================================================================\n");
        printf(
            "         %-40.40S %i %016llx %08x %016llx\n",
            L"kernel32.dll",
            pModuleEntryKernel32->fWoW64 ? 32 : 64,
            pModuleEntryKernel32->vaBase,
            pModuleEntryKernel32->cbImageSize,
            pModuleEntryKernel32->vaEntry
        );
    }
    else {
        printf("FAIL:    VMMDLL_Map_GetModuleFromNameU\n");
        VMMDLL_MemFree(pModuleEntryKernel32); pModuleEntryKernel32 = NULL;
        return 1;
    }


    // Close the VMM_HANDLE and clean up native resources.
    printf("------------------------------------------------------------\n");
    printf("# Close the VMM_HANDLE (hVMM) to clean up native resources. \n");
    ShowKeyPress();
    VMMDLL_MemFree(pModuleEntryKernel32); pModuleEntryKernel32 = NULL;
    VMMDLL_MemFree(pModuleEntryExplorer); pModuleEntryExplorer = NULL;
    printf("CALL:    VMMDLL_Close #1\n");
    VMMDLL_Close(hVMM);


    // Finish everything and exit!
    printf("------------------------------------------------------------\n");
    printf("# FINISHED EXAMPLES!                                        \n");
    ShowKeyPress();
    printf("FINISHED TEST CASES - EXITING!\n");

	return 0;
}
