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
    LPSTR stringSD = nullptr;
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

    // break up the SDDL string so it's more readable
    std::string str = stringSD;
    std::string toReplace = ")(";  
    std::string replaceWith = ")\n(";  

    size_t pos = 0;
    while ((pos = str.find(toReplace, pos)) != std::string::npos) {
        str.replace(pos, toReplace.length(), replaceWith);
        pos += replaceWith.length();  
    }

    // Print the string representation of the ACL.
    std::cout << "ACL for named pipe " << pipeName << "\n" << str << std::endl;

    // Cleanup.
    LocalFree(stringSD);
    LocalFree(pSD);
    CloseHandle(hPipe);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        std::cout << "Usage: DumpPipeAcl <pipename>" << std::endl;
        return -1;
    }

    DisplayACL(argv[1]);
    return 0;
}
