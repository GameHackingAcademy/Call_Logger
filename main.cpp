#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <Psapi.h>

#define READ_PAGE_SIZE 4096

int main(int argc, char** argv) {
    HANDLE process_snapshot = NULL;
    HANDLE thread_handle = NULL;
    HANDLE process_handle = NULL;

    PROCESSENTRY32 pe32 = { 0 };

    DWORD pid;
    DWORD continueStatus = DBG_CONTINUE;
    DWORD bytes_written = 0;

    BYTE instruction_break = 0xcc;
    BYTE instruction_call = 0xe8;

    DEBUG_EVENT debugEvent = { 0 };

    CONTEXT context = { 0 };

    bool first_break_has_occurred = false;

    HMODULE modules[128] = { 0 };
    MODULEINFO module_info = { 0 };

    DWORD bytes_read = 0;
    DWORD offset = 0;
    DWORD call_location = 0;
    DWORD call_location_bytes_read = 0;
    DWORD last_call_location = 0;

    unsigned char instructions[READ_PAGE_SIZE] = { 0 };

    int breakpoints_set = 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    process_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    Process32First(process_snapshot, &pe32);

    do {
        if (wcscmp(pe32.szExeFile, L"wesnoth.exe") == 0) {
            pid = pe32.th32ProcessID;

            process_handle = OpenProcess(PROCESS_ALL_ACCESS, true, pe32.th32ProcessID);
        }
    } while (Process32Next(process_snapshot, &pe32));

    DebugActiveProcess(pid);

    for (;;) {
        continueStatus = DBG_CONTINUE;

        if (!WaitForDebugEvent(&debugEvent, INFINITE))
            return 0;

        switch (debugEvent.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT:
            switch (debugEvent.u.Exception.ExceptionRecord.ExceptionCode)
            {
            case EXCEPTION_BREAKPOINT:
                if (!first_break_has_occurred) {
                    thread_handle = OpenThread(THREAD_ALL_ACCESS, true, debugEvent.dwThreadId);

                    printf("Attaching breakpoints\n");
                    EnumProcessModules(process_handle, modules, sizeof(modules), &bytes_read);
                    GetModuleInformation(process_handle, modules[0], &module_info, sizeof(module_info));
                    for (DWORD i = 0; i < module_info.SizeOfImage; i += READ_PAGE_SIZE) {
                        ReadProcessMemory(process_handle, (LPVOID)((DWORD)module_info.lpBaseOfDll + i), &instructions, READ_PAGE_SIZE, &bytes_read);
                        for (DWORD c = 0; c < bytes_read; c++) {
                            if (instructions[c] == instruction_call) {
                                offset = (DWORD)module_info.lpBaseOfDll + i + c;
                                ReadProcessMemory(process_handle, (LPVOID)(offset + 1), &call_location, 4, &call_location_bytes_read);
                                call_location += offset + 5;
                                if (call_location < (DWORD)module_info.lpBaseOfDll || call_location >(DWORD)module_info.lpBaseOfDll + module_info.SizeOfImage)
                                    continue;

                                if (offset != 0x0040e3d8 && offset != 0x0040e3ea && breakpoints_set < 2000) {
                                    WriteProcessMemory(process_handle, (void*)offset, &instruction_break, 1, &bytes_written);
                                    FlushInstructionCache(process_handle, (LPVOID)offset, 1);
                                    breakpoints_set++;
                                }
                            }
                        }
                    }

                    printf("Done attaching breakpoints\n");
                }
                else {
                    thread_handle = OpenThread(THREAD_ALL_ACCESS, true, debugEvent.dwThreadId);
                    if (thread_handle != NULL) {
                        context.ContextFlags = CONTEXT_ALL;
                        GetThreadContext(thread_handle, &context);

                        context.Eip--;
                        context.EFlags |= 0x100;

                        SetThreadContext(thread_handle, &context);
                        CloseHandle(thread_handle);

                        WriteProcessMemory(process_handle, (void*)context.Eip, &instruction_call, 1, &bytes_written);
                        FlushInstructionCache(process_handle, (LPVOID)context.Eip, 1);

                        last_call_location = context.Eip;
                    }
                }

                first_break_has_occurred = true;
                continueStatus = DBG_CONTINUE;
                break;
            case EXCEPTION_SINGLE_STEP:
                thread_handle = OpenThread(THREAD_ALL_ACCESS, true, debugEvent.dwThreadId);
                if (thread_handle != NULL) {
                    context.ContextFlags = CONTEXT_ALL;
                    GetThreadContext(thread_handle, &context);
                    CloseHandle(thread_handle);

                    WriteProcessMemory(process_handle, (void*)last_call_location, &instruction_break, 1, &bytes_written);
                    FlushInstructionCache(process_handle, (LPVOID)last_call_location, 1);

                    printf("0x%08x: call 0x%08x\n", last_call_location, context.Eip);
                    last_call_location = 0;
                }

                continueStatus = DBG_CONTINUE;
                break;
            default:
                continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                break;
            }
            break;
        default:
            continueStatus = DBG_EXCEPTION_NOT_HANDLED;
            break;
        }

        ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueStatus);
    }

    CloseHandle(process_handle);

    return 0;
}
