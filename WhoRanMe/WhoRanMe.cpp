/* 
    WhoRanMe - Find out how a program is being called
    Writes to ppidout.txt in the %USERPROFILE% directory

    Found my antivirus had left something malicious still attempting to execute and it wasn't obvious where it was being called from.
    This program logs how it was invoked and then traces its parentage as far as possible.

    Replace the program that is being run from some mysterious source with this program, and it will find out what it can about the parent and log it.
*/

#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

int getProcInfo(int pid, HANDLE h, PROCESSENTRY32 * ppe);

int main(int argc, char* argv[])
{
    int pid = -1;
    int ppid = -1;
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32);

    char sName[1024];
#pragma warning(disable : 4996)
    strcpy(sName, getenv("USERPROFILE"));
    strcat(sName, "\\ppidout.txt");
    FILE* fp = fopen(sName, "a");
    if (NULL == fp)
    {
        printf("Could not open output file (%s)\n", sName);
        return -1;
    }
    printf("Writing to %s\n", sName);

    pid = GetCurrentProcessId();        // Get our processID
    ppid = getProcInfo(pid, h, &pe);    // find our process descriptor
    if (-1 == ppid)
    {
        printf(" Can't find our PID???\n");
        fprintf(fp, " Can't find our PID???\n");
        return -2;
    }

    // We should always make it this far.  We now know about our process
    printf("PID: %i; PPID: %i", pid, pe.th32ParentProcessID);
    fprintf(fp, "PID: %i; PPID: %i", pid, pe.th32ParentProcessID);

    // Print any command line arguments
    printf(" Invoked as:");
    fprintf(fp, " Invoked as:");

    for (int ii = 0; ii < argc; ii++)
    {
        printf(" \"%s\"", argv[ii]);
        fprintf(fp, " \"%s\"", argv[ii]);
    }
    printf("\n");
    fprintf(fp, "\n");


    // Most processes will have a parent.  Warn if there is not one.
    ppid = getProcInfo(pe.th32ParentProcessID, h, &pe);     // Find our parent's descriptor
    if (-1 == ppid)
    {
        printf(" *Orphan*\n");
        fprintf(fp, " *Orphan*\n");
    }

    // Continue traceback until we can no longer find information about the next parent
    while (-1 != ppid)
    {
        printf(" By PID:%-5d PPID:%-5d - %ls\n", pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile);
        fprintf(fp, " By PID:%-5d PPID:%-5d - %ls\n", pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile);
        ppid = getProcInfo(pe.th32ParentProcessID, h, &pe);
    }

    fcloseall();
    CloseHandle(h);
}

int getProcInfo(int pid, HANDLE h, PROCESSENTRY32* ppe)
{
    if (Process32First(h, ppe)) {                   
        do {
            if (ppe->th32ProcessID == pid) {        // Search the process descriptors for the specified PID
                return pid;                         // If we find the PID, return it
            }
        } while (Process32Next(h, ppe));
    }

    return -1;  // Failure return
}
