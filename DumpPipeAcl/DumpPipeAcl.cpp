#include <Windows.h>
#include <Aclapi.h>
#include <Sddl.h>
#include <iostream>

void DisplayACL(const char* pipeName) {
    PACL pAcl = nullptr;
    PSECURITY_DESCRIPTOR pSD = nullptr;
    HANDLE hPipe = CreateFileA(pipeName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open named pipe: " << GetLastError() << std::endl;
        return;
    }

    DWORD dwRes = GetSecurityInfo(hPipe, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pAcl, NULL, &pSD);
    if (dwRes != ERROR_SUCCESS) {
        std::cerr << "Failed to get security info: " << dwRes << std::endl;
        CloseHandle(hPipe);
        return;
    }

    // Convert the ACL to a string.
    LPSTR stringSD;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorA(
        pSD,
        SDDL_REVISION_1,
        DACL_SECURITY_INFORMATION,
        &stringSD,
        NULL
    )) {
        std::cerr << "Failed to convert security descriptor: " << GetLastError() << std::endl;
        LocalFree(pSD);
        CloseHandle(hPipe);
        return;
    }

    // Print the string representation of the ACL.
    std::cout << "ACL for named pipe '" << pipeName << "': " << stringSD << std::endl;

    // Cleanup.
    LocalFree(stringSD);
    LocalFree(pSD);
    CloseHandle(hPipe);
}

int main() {
    const char* pipeName = "\\\\.\\\\pipe\\\\W32TIME_ALT";  // Replace this with your named pipe's path.
    DisplayACL(pipeName);
    return 0;
}
