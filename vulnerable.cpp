#include <iostream>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <string>

// VULNERABILITY 1: Buffer Overflow (Stack-based)
// Location: Line 13-20
// Description: strcpy doesn't check bounds, can overflow 'buffer'
// Impact: Can overwrite return address, lead to code execution
void vulnerable_strcpy(const char* input) {
    char buffer[64];  // Small fixed-size buffer
    
    // DANGEROUS: No bounds checking!
    strcpy(buffer, input);  // Can write past end of buffer
    
    std::cout << "You entered: " << buffer << std::endl;
}

// VULNERABILITY 2: Format String Attack
// Location: Line 26
// Description: User input used directly in printf format string
// Impact: Can read/write arbitrary memory, information disclosure
void vulnerable_printf(const char* user_input) {
    // DANGEROUS: User controls format string!
    printf(user_input);  // Should be: printf("%s", user_input);
    printf("\n");
}

// VULNERABILITY 3: Use After Free
// Location: Line 37-40
// Description: Memory accessed after being freed
// Impact: Can lead to crashes or arbitrary code execution
void use_after_free_bug() {
    char* ptr = (char*)malloc(100);
    strcpy(ptr, "Hello World");
    
    free(ptr);  // Memory is freed here
    
    // DANGEROUS: Using freed memory!
    printf("Content: %s\n", ptr);  // Use after free
    strcpy(ptr, "Modified");        // Write to freed memory
}

// VULNERABILITY 4: Integer Overflow leading to Buffer Overflow
// Location: Line 49-54
// Description: Integer overflow can make size appear small
// Impact: Allocation of small buffer but large copy operation
void integer_overflow_vuln(unsigned int count) {
    // DANGEROUS: count * 4 might overflow!
    unsigned int size = count * sizeof(int);
    
    if (size < 1000) {  // Check seems safe but can be bypassed
        int* buffer = (int*)malloc(size);
        // If size overflowed, this copies more than allocated
        memset(buffer, 0xFF, count * sizeof(int));
        free(buffer);
    }
}

// VULNERABILITY 5: NULL Pointer Dereference
// Location: Line 64-66
// Description: malloc can return NULL, not checked
// Impact: Segmentation fault, potential denial of service
void null_pointer_deref(size_t size) {
    char* ptr = (char*)malloc(size);
    // DANGEROUS: No NULL check!
    strcpy(ptr, "Hello");  // Crash if malloc failed
    free(ptr);
}

// VULNERABILITY 6: Race Condition (TOCTOU - Time of Check Time of Use)
// Location: Line 73-79
// Description: File status changes between check and use
// Impact: Privilege escalation, unexpected file access
void toctou_vulnerability(const char* filename) {
    // Check file permissions
    if (access(filename, R_OK) == 0) {
        // DANGEROUS: File could change between check and use!
        sleep(1);  // Simulates delay - real race window
        
        FILE* file = fopen(filename, "r");  // File might be different now
        if (file) {
            // Process file...
            fclose(file);
        }
    }
}

// VULNERABILITY 7: Command Injection
// Location: Line 88
// Description: User input passed directly to system()
// Impact: Arbitrary command execution
void command_injection(const char* filename) {
    char command[256];
    // DANGEROUS: No input sanitization!
    sprintf(command, "cat %s", filename);  // User can inject commands
    system(command);  // Executes user-controlled command
}

// VULNERABILITY 8: Memory Leak
// Location: Line 98-103
// Description: Allocated memory never freed in error path
// Impact: Memory exhaustion over time
void memory_leak_bug(bool condition) {
    char* data = (char*)malloc(1000);
    
    if (condition) {
        return;  // DANGEROUS: Memory leak! 'data' never freed
    }
    
    free(data);  // Only freed in success path
}

// Main function to demonstrate vulnerabilities
int main(int argc, char* argv[]) {
    std::cout << "=== Vulnerable Code Examples for Joern Practice ===" << std::endl;
    
    // Example usage (commented out for safety):
    
    // VULNERABILITY 1: Buffer overflow
    // vulnerable_strcpy("This is a very long string that will overflow the 64-byte buffer and corrupt memory");
    
    // VULNERABILITY 2: Format string
    // vulnerable_printf("%x %x %x %x");  // Reads stack memory
    
    // VULNERABILITY 3: Use after free
    // use_after_free_bug();
    
    // VULNERABILITY 4: Integer overflow
    // integer_overflow_vuln(0xFFFFFFFF);  // Will overflow
    
    // VULNERABILITY 5: NULL pointer dereference
    // null_pointer_deref(SIZE_MAX);  // malloc likely to fail
    
    // VULNERABILITY 6: TOCTOU race condition
    // toctou_vulnerability("/etc/passwd");
    
    // VULNERABILITY 7: Command injection
    // command_injection("file.txt; rm -rf /");  // Dangerous!
    
    // VULNERABILITY 8: Memory leak
    // memory_leak_bug(true);
    
    std::cout << "Code compiled successfully. Use with Joern to find vulnerabilities!" << std::endl;
    
    return 0;
}

/*
=== JOERN PRACTICE QUERIES ===

After parsing this code with Joern, try these queries:

1. Find buffer overflow vulnerabilities:
   cpg.call.name("strcpy").l

2. Find format string vulnerabilities:
   cpg.call.name("printf").argument(1).isIdentifier.l

3. Find use-after-free patterns:
   cpg.call.name("free").l
   cpg.call.name("malloc").l

4. Find command injection:
   cpg.call.name("system").l

5. Find memory allocation without free:
   cpg.call.name("malloc").l
   cpg.call.name("free").l

6. Find dangerous string functions:
   cpg.call.name("(strcpy|strcat|sprintf|gets)").l

7. Analyze data flows to sources and sinks:
   cpg.method.name("main").parameter.reachableBy(cpg.call.name("strcpy")).l

Remember: This code is intentionally vulnerable for educational purposes only!
Never use these patterns in production code.
*/