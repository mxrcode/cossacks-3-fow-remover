#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <iostream>
#include <vector>
#include <cstdint>

// Convert a narrow-character string to a wide-character string
WCHAR* char_to_wchar(const char* str)
{
    int size = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    WCHAR* wstr = new WCHAR[size];
    MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, size);
    return wstr;
}

DWORD get_process_id_by_name(const WCHAR* process_name)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &process_entry)) {
        do {
            if (wcscmp(process_entry.szExeFile, process_name) == 0) {
                CloseHandle(snapshot);
                return process_entry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &process_entry));
    }

    CloseHandle(snapshot);
    return 0;
}

byte* memory_reader(DWORD pid, uintptr_t address, BOOL change_protection = 0)
{
    size_t size = sizeof(DWORD);

    static byte* bytes = new byte[size];

    HANDLE ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    // Allow READ & WRITE for the specified memory area
    DWORD t_memory_protect = 0; // for original protect value
    if (change_protection == 1) VirtualProtectEx(ph, (void*)address, size, PAGE_EXECUTE_READWRITE, &t_memory_protect);

    ReadProcessMemory(ph, (void*)address, bytes, size, 0);

    // Restore memory area protection settings to original values
    if (change_protection == 1) VirtualProtectEx(ph, (void*)address, size, t_memory_protect, &t_memory_protect);

    CloseHandle(ph);

    return bytes;
}

void memory_writer(DWORD pid, uintptr_t address, DWORD new_value, BOOL change_protection = 0)
{
    size_t size = sizeof(DWORD);

    HANDLE ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    // Allow READ & WRITE for the specified memory area
    DWORD t_memory_protect = 0; // for original protect value
    if (change_protection == 1) VirtualProtectEx(ph, (void*)address, size, PAGE_EXECUTE_READWRITE, &t_memory_protect);

    WriteProcessMemory(ph, (void*)address, &new_value, size, 0);

    // Restore memory area protection settings to original values
    if (change_protection == 1) VirtualProtectEx(ph, (void*)address, size, t_memory_protect, &t_memory_protect);

    CloseHandle(ph);

    return;
}

uintptr_t pointer_reader(DWORD pid, uintptr_t address, std::vector<DWORD> offsets, BOOL change_protection = 0)
{
    byte* t;

    for (int i = 0; i < offsets.size(); i++)
    {
        t = memory_reader(pid, (address + offsets[i]));
        memcpy(&address, t, sizeof(address));
    }

    return address;
}

uintptr_t pointer_reader(DWORD pid, uintptr_t address, std::vector<DWORD> offsets, uintptr_t& value_addr, BOOL change_protection = 0)
{
    byte* t;

    for (int i = 0; i < offsets.size(); i++)
    {
        if (i == (offsets.size() - 1)) {
            value_addr = address + offsets[i];
        }

        t = memory_reader(pid, (address + offsets[i]));
        memcpy(&address, t, sizeof(address));
    }

    return address;
}

uintptr_t get_module_base_address(DWORD pid) {

    // Obtain a handle to the target process
    HANDLE ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (ph == 0) {
        std::cerr << "Error: could not open process" << "\n";
        return 1;
    }

    // Enumerate the modules in the target process
    HMODULE module_handles[1024];
    DWORD num_modules;
    if (!EnumProcessModules(ph, module_handles, sizeof(module_handles), &num_modules)) {
        std::cerr << "Error: could not enumerate modules" << "\n";
        CloseHandle(ph);
        return 1;
    }

    // Iterate over the modules and print their base addresses
    uintptr_t module_base_address;
    for (DWORD i = 0; i < (num_modules / sizeof(HMODULE)); i++) {
        MODULEINFO module_info;
        if (GetModuleInformation(ph, module_handles[i], &module_info, sizeof(module_info))) {
            //byte* bytes = memory_reader(pid, reinterpret_cast<uintptr_t>(module_info.lpBaseOfDll), 1);
            //memcpy(&module_base_address, bytes, sizeof(module_base_address));
            //std::cout << "Base address of module " << i << ": 0x" << std::hex << module_info.lpBaseOfDll;
            //std::cout << " (0x" << std::hex << module_base_address << ")";
            //std::cout << "\t" << "break..." << "\n";
            module_base_address = reinterpret_cast<uintptr_t>(module_info.lpBaseOfDll);
            break;
        }
    }

    // Clean up
    CloseHandle(ph);

    return module_base_address;
}

int main()
{
    const char* process_name = "cossacks.exe";

    DWORD pid = get_process_id_by_name(char_to_wchar(process_name));
    if (pid == 0) {
        std::cerr << "Could not find process " << process_name << "\n";
        return 1;
    }

    std::cout << "Process ID:\t\t" << pid << "\n";
    std::cout << "\n";

    uintptr_t base_address = get_module_base_address(pid) + 0x4FA5D8; // Just find it with Cheat Engine
    byte* bytes = memory_reader(pid, base_address, 1);
    memcpy(&base_address, bytes, sizeof(base_address));

    std::vector<DWORD> offsets = { 0x3BC, 0x194 };
    std::cout << "Unchanged Value:\t" << std::hex << pointer_reader(pid, base_address, offsets) << "\n";

    uintptr_t value_addr;
    DWORD changed_value = pointer_reader(pid, base_address, offsets, value_addr);

    memory_writer(pid, value_addr, ((changed_value == 0) ? 1 : 0 ));

    std::cout << "Value Addr:     \t" << std::hex << value_addr << "\n";
    std::cout << "Changed Value:  \t" << changed_value << "\n";
    std::cout << "\n";

    if (changed_value == 1) {
        std::cout << "Fog of War has been successfully removed" << "\n";
    }
    else {
        std::cout << "Fog of War has been successfully returned to the game" << "\n";
    }

    return 0;
}