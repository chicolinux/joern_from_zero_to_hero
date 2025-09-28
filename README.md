# Introduction to Joern

I've created a comprehensive vulnerable C++ program with 8 different types of common security vulnerabilities. Each vulnerability is clearly commented with:

- Location: Where the vulnerability occurs
- Description: What makes it vulnerable
- Impact: Potential security consequences

# Vulnerabilities Included:

1. Buffer Overflow - Classic stack overflow with strcpy()
2. Format String Attack - User-controlled format strings
3. Use After Free - Memory corruption vulnerability
4. Integer Overflow - Leading to buffer overflow
5. NULL Pointer Dereference - Missing malloc checks
6. Race Condition (TOCTOU) - Time-of-check-time-of-use
7. Command Injection - Unsanitized input to system()
8. Memory Leak - Missing free() in error path

## How to Use with Joern:

1. Save the code to a file (e.g., vulnerable.cpp)
2. Parse with Joern:
joern-parse /path/to/vulnerable.cpp --output vulnerable.bin
joern --import vulnerable.bin

3. Try the practice queries included at the bottom of the code to find each vulnerability type
4. Experiment with data flow analysis to trace how user input reaches dangerous functions

This gives you a realistic playground to learn Joern's capabilities for static analysis and vulnerability detection. The code is designed to be educational - each vulnerability represents real-world patterns you might encounter in actual codebases.
Start with the simple queries I've included, then try creating more complex ones as you get comfortable with Joern's query language!RetryClaude does not have the ability to run the code it generates yet.
