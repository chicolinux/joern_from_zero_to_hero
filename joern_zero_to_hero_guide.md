# Joern Zero to Hero: Complete Mastery Guide

## Table of Contents
1. [Prerequisites and Setup](#1-prerequisites-and-setup)
2. [Understanding Code Property Graphs](#2-understanding-code-property-graphs)
3. [Basic Joern Operations](#3-basic-joern-operations)
4. [Exploring the CPG Structure](#4-exploring-the-cpg-structure)
5. [Basic Queries and Traversals](#5-basic-queries-and-traversals)
6. [Advanced Query Techniques](#6-advanced-query-techniques)
7. [Data Flow Analysis](#7-data-flow-analysis)
8. [Control Flow Analysis](#8-control-flow-analysis)
9. [Vulnerability Detection Patterns](#9-vulnerability-detection-patterns)
10. [Custom Scripts and Automation](#10-custom-scripts-and-automation)
11. [Performance Optimization](#11-performance-optimization)
12. [Real-World Case Studies](#12-real-world-case-studies)

---

## 1. Prerequisites and Setup

### System Requirements
- **OS**: Ubuntu 20.04+ (or other Linux distributions)
- **Java**: JDK 19 or newer
- **Memory**: At least 8GB RAM (16GB+ recommended for large codebases)
- **Storage**: 10GB+ free space

### Installation Steps

```bash
# 1. Install Java 19+ if not already installed
sudo apt update
sudo apt install openjdk-19-jdk

# 2. Verify Java installation
java -version
javac -version

# 3. Install Joern
mkdir ~/joern && cd ~/joern
curl -L "https://github.com/joernio/joern/releases/latest/download/joern-install.sh" -o joern-install.sh
chmod u+x joern-install.sh
./joern-install.sh --interactive

# 4. Add Joern to PATH (add to ~/.bashrc)
echo 'export PATH="$HOME/joern:$PATH"' >> ~/.bashrc
source ~/.bashrc

# 5. Verify installation
joern --help
```

### Test Installation
```bash
# Create a simple test file
echo 'int main() { return 0; }' > test.c

# Parse it with Joern
joern-parse test.c --output test.bin

# Verify the CPG was created
ls -la test.bin/
```

---

## 2. Understanding Code Property Graphs

### What is a CPG?
A Code Property Graph combines three graph representations:
- **AST (Abstract Syntax Tree)**: Program structure
- **CFG (Control Flow Graph)**: Execution flow
- **PDG (Program Dependence Graph)**: Data and control dependencies

### CPG Node Types
```scala
// Key node types you'll encounter:
- FILE          // Source files
- NAMESPACE     // Namespaces/packages
- TYPE_DECL     // Class/struct declarations
- METHOD        // Functions/methods
- PARAMETER     // Function parameters
- LOCAL         // Local variables
- IDENTIFIER    // Variable references
- LITERAL       // Constant values
- CALL          // Function calls
- RETURN        // Return statements
- IF            // Conditional statements
- WHILE/FOR     // Loops
- BLOCK         // Code blocks
```

### Edge Types
```scala
// Important edge types:
- AST           // Abstract syntax tree edges
- CFG           // Control flow edges
- REF           // Reference edges (variable usage)
- CALL          // Call edges
- ARGUMENT      // Argument edges
- RECEIVER      // Method receiver edges
- REACHING_DEF  // Data flow edges
```

---

## 3. Basic Joern Operations

### Starting Joern

```bash
# Method 1: Interactive shell
joern

# Method 2: With a pre-loaded CPG
joern --import /path/to/cpg.bin

# Method 3: Parse and import in one step
joern-parse /path/to/code --output code.bin
joern --import code.bin
```

### Essential Commands

#### Help System
```scala
// In Joern shell:
help                    // List all available commands
help("METHOD_NAME")    // Help for specific method
browse(cpg.METHOD)     // Browse available methods on objects
```

#### Basic Navigation
```scala
// Show available methods on cpg object
cpg.help

// List all methods in the CPG
cpg.method.l           // .l converts to list

// Count methods
cpg.method.size        // Returns count as integer

// Get first method
cpg.method.head        // Returns first element

// Take first N methods  
cpg.method.take(5).l   // Take first 5 methods
```

#### Exiting and Saving
```scala
// Exit Joern
exit

// Save current workspace
save("my_analysis")

// Load saved workspace
load("my_analysis")
```

---

## 4. Exploring the CPG Structure

### File and Namespace Exploration

```scala
// List all files in the CPG
cpg.file.l

// Get file names only
cpg.file.name.l

// Explore namespaces
cpg.namespace.l
cpg.namespace.name.l

// Filter files by extension
cpg.file.name(".*\\.cpp").l
cpg.file.name(".*\\.h").l
```

### Method Exploration

```scala
// List all methods
cpg.method.l

// Get method names
cpg.method.name.l

// Get method signatures
cpg.method.signature.l

// Filter methods by name
cpg.method.name("main").l
cpg.method.name(".*vulnerable.*").l    // Regex matching

// Get method parameters
cpg.method.name("main").parameter.l
cpg.method.name("main").parameter.name.l

// Get method return types
cpg.method.returnType.l
```

### Variable and Type Analysis

```scala
// Local variables
cpg.local.l
cpg.local.name.l
cpg.local.typeFullName.l

// Parameters
cpg.parameter.l
cpg.parameter.name.l
cpg.parameter.typeFullName.l

// Identifiers (variable usage)
cpg.identifier.l
cpg.identifier.name.l

// Literals (constants)
cpg.literal.l
cpg.literal.code.l
```

---

## 5. Basic Queries and Traversals

### Finding Function Calls

```scala
// All function calls
cpg.call.l

// Function call names
cpg.call.name.l

// Specific function calls
cpg.call.name("malloc").l
cpg.call.name("strcpy").l
cpg.call.name("printf").l

// Calls with regex
cpg.call.name("str.*").l           // All calls starting with "str"
cpg.call.name(".*cpy").l           // All calls ending with "cpy"
```

### Analyzing Call Arguments

```scala
// Get arguments of strcpy calls
cpg.call.name("strcpy").argument.l

// Get argument code (source representation)
cpg.call.name("strcpy").argument.code.l

// Get specific argument positions
cpg.call.name("strcpy").argument(1).l      // First argument (0-indexed)
cpg.call.name("strcpy").argument(2).l      // Second argument

// Chain operations
cpg.call.name("strcpy").argument(1).code.l  // Code of first arguments
```

### Method Body Analysis

```scala
// Get method body
cpg.method.name("vulnerable_strcpy").body.l

// All calls within a method
cpg.method.name("vulnerable_strcpy").call.l
cpg.method.name("vulnerable_strcpy").call.name.l

// All variables in a method
cpg.method.name("vulnerable_strcpy").local.l
cpg.method.name("vulnerable_strcpy").local.name.l
```

### Filtering and Conditions

```scala
// Using where() for complex conditions
cpg.method.where(_.parameter.size > 2).l    // Methods with more than 2 parameters

// Multiple conditions
cpg.call.name("malloc").where(_.argument.size == 1).l

// Combining filters
cpg.method.name(".*vuln.*").call.name("strcpy").l
```

---

## 6. Advanced Query Techniques

### Traversing Relationships

```scala
// From calls back to containing methods
cpg.call.name("strcpy").method.l
cpg.call.name("strcpy").method.name.l

// From methods to their calls
cpg.method.call.name("malloc").l

// From parameters to their methods
cpg.parameter.method.name.l

// From identifiers to their declarations
cpg.identifier.referencedParameter.l
cpg.identifier.referencedLocal.l
```

### Using Map and Filter Operations

```scala
// Map over results
cpg.method.map(_.name).l
cpg.call.map(m => (m.name, m.lineNumber)).l

// Filter with predicates
cpg.method.filter(_.name.startsWith("vulnerable")).l
cpg.call.filter(_.argument.size > 2).l

// Complex transformations
cpg.method
  .filter(_.parameter.size > 0)
  .map(m => (m.name, m.parameter.size))
  .l
```

### Grouping and Aggregation

```scala
// Group calls by name
cpg.call.groupBy(_.name).view.mapValues(_.size).toMap

// Count methods per file
cpg.method.groupBy(_.file.name).view.mapValues(_.size).toMap

// Find most called functions
cpg.call.groupBy(_.name).view.mapValues(_.size).toSeq.sortBy(-_._2)
```

### Pattern Matching and Complex Queries

```scala
// Using collect for pattern matching
cpg.call.name.collect {
  case name if name.startsWith("str") => s"String function: $name"
  case name if name.contains("alloc") => s"Memory function: $name"
}.l

// Nested traversals
cpg.method
  .where(_.call.name("malloc").nonEmpty)  // Methods that call malloc
  .where(_.call.name("free").isEmpty)     // But don't call free
  .name.l                                 // Potential memory leaks!
```

---

## 7. Data Flow Analysis

### Basic Data Flow Concepts

Data flow analysis tracks how data moves through a program:
- **Sources**: Where data enters (user input, file reads, network)
- **Sinks**: Where data is used (system calls, output functions)  
- **Sanitizers**: Functions that clean/validate data

### Finding Data Flow Sources

```scala
// Common source functions
val sources = cpg.call.name("(gets|scanf|fgets|read|recv).*").l

// Parameters (user input)
val paramSources = cpg.method.parameter.l

// File operations
val fileSources = cpg.call.name("(fread|getc|fgetc)").l
```

### Finding Data Flow Sinks

```scala
// Command execution sinks
val cmdSinks = cpg.call.name("(system|exec.*|popen)").l

// Memory operations (potential overflows)
val memSinks = cpg.call.name("(strcpy|strcat|sprintf|memcpy)").l

// Output sinks
val outputSinks = cpg.call.name("(printf|fprintf|puts)").l
```

### Reachability Analysis

```scala
// Basic reachability from sources to sinks
cpg.call.name("gets")
  .argument(1)
  .reachableBy(cpg.call.name("strcpy").argument(2))
  .l

// More complex data flow
val userInput = cpg.method.parameter
val dangerousCalls = cpg.call.name("system")

// Find if user input can reach system calls
userInput.reachableBy(dangerousCalls.argument).l
```

### Advanced Data Flow Tracking

```scala
// Track data flow through specific variables
cpg.identifier.name("buffer")
  .reachableBy(cpg.call.name("strcpy").argument(1))
  .l

// Multi-hop data flow analysis
cpg.call.name("scanf")
  .argument
  .reachableBy(cpg.call.name("system").argument)
  .flows.l  // Get full flow paths

// Data flow with filters
cpg.call.name("malloc")
  .where(_.reachableBy(cpg.method.parameter).nonEmpty)
  .l  // malloc calls reachable from parameters
```

### Custom Data Flow Queries

```scala
// Define helper functions
def findFlows(source: String, sink: String) = {
  cpg.call.name(source)
    .argument
    .reachableBy(cpg.call.name(sink).argument)
    .flows.l
}

// Usage
findFlows("scanf", "system")     // Command injection flows
findFlows("fgets", "strcpy")     // Buffer overflow flows
findFlows("recv", "sprintf")     // Network to format string flows
```

---

## 8. Control Flow Analysis

### Understanding Control Flow

```scala
// Get control flow successors
cpg.method.name("main").controlStructure.l

// Control flow from a specific node
val ifNode = cpg.controlStructure.controlStructureType("IF").head
ifNode.cfgNext.l  // Next nodes in control flow

// Control flow predecessors  
ifNode.cfgPrev.l  // Previous nodes in control flow
```

### Loop Analysis

```scala
// Find all loops
cpg.controlStructure.controlStructureType("(FOR|WHILE|DO)").l

// Loops in specific methods
cpg.method.name("vulnerable_function")
  .controlStructure
  .controlStructureType("FOR")
  .l

// Calls within loops (potential performance issues)
cpg.controlStructure.controlStructureType("FOR")
  .astChildren
  .isCall
  .name("malloc")
  .l
```

### Conditional Analysis

```scala
// Find all if statements
cpg.controlStructure.controlStructureType("IF").l

// Get condition expressions
cpg.controlStructure.controlStructureType("IF")
  .condition
  .l

// Calls in conditional branches
cpg.controlStructure.controlStructureType("IF")
  .when.call.name.l  // Calls in 'then' branch

cpg.controlStructure.controlStructureType("IF")
  .whenFalse.call.name.l  // Calls in 'else' branch
```

### Path Analysis

```scala
// Find all execution paths through a method
def findPaths(methodName: String) = {
  val method = cpg.method.name(methodName).head
  method.cfgFirst.repeat(_.cfgNext)(_.emit.until(_.cfgNext.isEmpty)).l
}

// Paths containing specific calls
cpg.method.name("main")
  .cfgFirst
  .repeat(_.cfgNext)(_.emit)
  .isCall.name("malloc")
  .l
```

---

## 9. Vulnerability Detection Patterns

### Buffer Overflow Detection

```scala
// Basic buffer overflow pattern: dangerous string functions
val dangerousStringFuncs = List("strcpy", "strcat", "sprintf", "gets")
val bufferOverflowCalls = cpg.call.name(s"(${dangerousStringFuncs.mkString("|")})").l

// Enhanced detection with context
def findBufferOverflows() = {
  cpg.call.name("strcpy")
    .where(_.argument(2).isIdentifier)  // Second arg is variable
    .where(_.argument(1).isLiteral.not) // First arg is not literal (unknown size)
    .l
}

// Stack buffer analysis
cpg.local.typeFullName("char\\[.*\\]")  // Local char arrays
  .referencingIdentifiers
  .inCall.name("strcpy")
  .argument(1)
  .l
```

### Use-After-Free Detection

```scala
// Find free calls
val freeCalls = cpg.call.name("free").l

// Find potential use-after-free
def findUseAfterFree() = {
  cpg.call.name("free")
    .argument(1)
    .isIdentifier
    .referencingIdentifiers
    .inCall
    .where(_.lineNumber.isDefined)
    .filter(call => {
      val freeCall = call.argument(1).isIdentifier.inCall.name("free").head
      call.lineNumber.get > freeCall.lineNumber.get
    })
    .l
}
```

### Format String Vulnerabilities

```scala
// Format string vulnerabilities
cpg.call.name("printf")
  .where(_.argument(1).isIdentifier)  // Format string is variable
  .l

cpg.call.name("sprintf")
  .where(_.argument(2).isIdentifier)  // Format string is variable (second arg for sprintf)
  .l

// More comprehensive check
def findFormatStringVulns() = {
  val formatFunctions = List("printf", "fprintf", "sprintf", "snprintf")
  formatFunctions.flatMap { funcName =>
    val formatArgIndex = if (funcName.contains("printf")) 1 else 2
    cpg.call.name(funcName)
      .where(_.argument(formatArgIndex).isIdentifier)
      .l
  }
}
```

### Command Injection Detection

```scala
// Command injection in system calls
cpg.call.name("system")
  .argument(1)
  .isIdentifier
  .l

// More sophisticated detection
def findCommandInjection() = {
  val cmdFunctions = List("system", "execve", "popen")
  cmdFunctions.flatMap { func =>
    cpg.call.name(func)
      .argument(1)
      .reachableBy(cpg.method.parameter)  // Reachable from user input
      .l
  }
}
```

### Memory Leak Detection

```scala
// Basic memory leak: malloc without free
def findMemoryLeaks() = {
  val methodsWithMalloc = cpg.method.where(_.call.name("malloc").nonEmpty).l
  val methodsWithFree = cpg.method.where(_.call.name("free").nonEmpty).name.toSet
  
  methodsWithMalloc.filterNot(m => methodsWithFree.contains(m.name))
}

// More sophisticated: track malloc return values
cpg.call.name("malloc")
  .where(_.inAssignment.target.referencingIdentifiers.inCall.name("free").isEmpty)
  .l
```

### Integer Overflow Detection

```scala
// Potential integer overflows in size calculations
cpg.call.name("malloc")
  .argument(1)
  .where(_.ast.isCall.name("\\*").nonEmpty)  // Size involves multiplication
  .l

// Buffer allocations with arithmetic
cpg.call.name("(malloc|calloc)")
  .argument
  .ast
  .isCall.name("(\\+|\\-|\\*|/)")
  .l
```

---

## 10. Custom Scripts and Automation

### Writing Joern Scripts

Create a script file (e.g., `my_analysis.sc`):

```scala
// File: vulnerability_scanner.sc

import io.joern.console._

// Define vulnerability detection functions
def findBufferOverflows(cpg: Cpg) = {
  cpg.call.name("strcpy")
    .where(_.argument(2).isIdentifier)
    .map(call => Map(
      "function" -> call.name,
      "file" -> call.file.name.headOption.getOrElse("unknown"),
      "line" -> call.lineNumber.getOrElse(-1),
      "code" -> call.code
    ))
    .l
}

def findFormatStringVulns(cpg: Cpg) = {
  cpg.call.name("printf")
    .where(_.argument(1).isIdentifier)
    .map(call => Map(
      "function" -> call.name,
      "file" -> call.file.name.headOption.getOrElse("unknown"),
      "line" -> call.lineNumber.getOrElse(-1),
      "code" -> call.code
    ))
    .l
}

// Main analysis function
def runVulnerabilityAnalysis(cpg: Cpg) = {
  println("=== Vulnerability Analysis Report ===")
  
  val bufferOverflows = findBufferOverflows(cpg)
  println(s"Buffer Overflows Found: ${bufferOverflows.size}")
  bufferOverflows.foreach(println)
  
  val formatStringVulns = findFormatStringVulns(cpg)
  println(s"Format String Vulnerabilities Found: ${formatStringVulns.size}")
  formatStringVulns.foreach(println)
}

// Auto-run analysis
if (workspace.cpg.isDefined) {
  runVulnerabilityAnalysis(cpg)
}
```

### Running Custom Scripts

```bash
# Method 1: Load script in interactive mode
joern --import code.bin
joern> loadCpg("code.bin")
joern> :load vulnerability_scanner.sc

# Method 2: Run script non-interactively
joern --script vulnerability_scanner.sc --import code.bin
```

### Batch Processing Scripts

```scala
// File: batch_analysis.sc

import java.io.File
import java.nio.file.{Files, Paths}

def analyzeProject(projectPath: String) = {
  println(s"Analyzing project: $projectPath")
  
  // Parse the project
  val cpgPath = s"${projectPath}.bin"
  Process(s"joern-parse $projectPath --output $cpgPath").!
  
  // Load CPG
  loadCpg(cpgPath)
  
  // Run analysis
  runVulnerabilityAnalysis(cpg)
  
  // Generate report
  val reportPath = s"${projectPath}_report.txt"
  // ... generate report logic
  
  // Cleanup
  close
}

// Analyze multiple projects
val projects = List("/path/to/project1", "/path/to/project2")
projects.foreach(analyzeProject)
```

### Export and Reporting Functions

```scala
// File: reporting.sc

import java.io.{File, PrintWriter}
import java.time.LocalDateTime

def generateVulnerabilityReport(cpg: Cpg, outputPath: String) = {
  val writer = new PrintWriter(new File(outputPath))
  
  try {
    writer.println(s"Vulnerability Report Generated: ${LocalDateTime.now}")
    writer.println("=" * 60)
    
    // Buffer Overflows
    val bufferOverflows = findBufferOverflows(cpg)
    writer.println(s"Buffer Overflows: ${bufferOverflows.size}")
    bufferOverflows.foreach { vuln =>
      writer.println(s"  ${vuln("file")}:${vuln("line")} - ${vuln("code")}")
    }
    
    // Format String Vulnerabilities
    val formatVulns = findFormatStringVulns(cpg)
    writer.println(s"Format String Vulnerabilities: ${formatVulns.size}")
    formatVulns.foreach { vuln =>
      writer.println(s"  ${vuln("file")}:${vuln("line")} - ${vuln("code")}")
    }
    
    writer.println("=" * 60)
    writer.println("Report Complete")
    
  } finally {
    writer.close()
  }
}

// CSV Export function
def exportToCSV(vulnerabilities: List[Map[String, Any]], filename: String) = {
  val writer = new PrintWriter(new File(filename))
  
  try {
    // Header
    writer.println("Type,Function,File,Line,Code")
    
    // Data
    vulnerabilities.foreach { vuln =>
      val type_ = vuln.getOrElse("type", "unknown")
      val function = vuln.getOrElse("function", "")
      val file = vuln.getOrElse("file", "")
      val line = vuln.getOrElse("line", "")
      val code = vuln.getOrElse("code", "").toString.replace(",", ";")
      
      writer.println(s"$type_,$function,$file,$line,$code")
    }
  } finally {
    writer.close()
  }
}
```

---

## 11. Performance Optimization

### CPG Size Management

```scala
// Check CPG statistics
cpg.graph.nodes().asScala.size    // Total nodes
cpg.graph.edges().asScala.size    // Total edges

// Memory usage monitoring
val runtime = Runtime.getRuntime
val usedMemory = runtime.totalMemory - runtime.freeMemory
println(s"Memory used: ${usedMemory / 1024 / 1024} MB")
```

### Query Optimization

```scala
// BAD: Inefficient query
cpg.all.where(_.isCall).where(_.name == "malloc").l

// GOOD: More efficient  
cpg.call.name("malloc").l

// BAD: Multiple traversals
val methods = cpg.method.l
methods.filter(_.call.name("malloc").nonEmpty)

// GOOD: Single traversal
cpg.method.where(_.call.name("malloc").nonEmpty).l

// Use indices when available
cpg.call.nameExact("malloc").l  // Uses index if available
```

### Streaming and Lazy Evaluation

```scala
// Use iterators for large results
cpg.call.nameExact("malloc").iterator.take(10).toList

// Lazy evaluation with view
cpg.method.view.filter(_.parameter.size > 2).take(5).toList

// Process in chunks
def processInChunks[T](items: List[T], chunkSize: Int)(process: List[T] => Unit) = {
  items.grouped(chunkSize).foreach(process)
}

val allMethods = cpg.method.l
processInChunks(allMethods, 100) { chunk =>
  // Process chunk of 100 methods
  chunk.foreach(analyzeMethod)
}
```

### Memory Management

```scala
// Clean up unused CPGs
close  // Close current CPG

// Garbage collection hints
System.gc()

// Monitor memory during analysis
def withMemoryMonitoring[T](operation: => T): T = {
  val runtime = Runtime.getRuntime
  val beforeMemory = runtime.totalMemory - runtime.freeMemory
  
  val result = operation
  
  val afterMemory = runtime.totalMemory - runtime.freeMemory
  println(s"Memory delta: ${(afterMemory - beforeMemory) / 1024 / 1024} MB")
  
  result
}

// Usage
val result = withMemoryMonitoring {
  cpg.call.name("malloc").l
}
```

---

## 12. Real-World Case Studies

### Case Study 1: OpenSSL Heartbleed Analysis

```scala
// Simulate analyzing Heartbleed-like vulnerability
def analyzeHeartbleedPattern(cpg: Cpg) = {
  // Look for memcpy with user-controlled length
  cpg.call.name("memcpy")
    .where(_.argument(3).reachableBy(cpg.method.parameter))  // Length from parameter
    .where(_.argument(2).reachableBy(cpg.method.parameter))  // Source from parameter
    .l
}

// Enhanced analysis with bounds checking
def findMissingBoundsChecks(cpg: Cpg) = {
  cpg.call.name("memcpy")
    .filterNot { call =>
      // Check if there's a bounds check before this call
      val method = call.method
      val boundsChecks = method.call.name("(strlen|sizeof|min|MAX)").l
      boundsChecks.exists(_.lineNumber.exists(_ < call.lineNumber.getOrElse(Int.MaxValue)))
    }
    .l
}
```

### Case Study 2: SQL Injection in C Applications

```scala
// Find potential SQL injection in C code
def findSQLInjection(cpg: Cpg) = {
  val sqlFunctions = List("sqlite3_exec", "mysql_query", "PQexec")
  
  sqlFunctions.flatMap { func =>
    cpg.call.name(func)
      .argument(2)  // SQL query argument
      .reachableBy(cpg.method.parameter)  // Reachable from user input
      .whereNot(_.reachableBy(cpg.call.name("(escape|sanitize|prepare).*")))  // Not sanitized
      .l
  }
}

// Find string concatenation in SQL contexts
def findSQLStringConcatenation(cpg: Cpg) = {
  cpg.call.name("strcat")
    .where(_.argument.code(".*SELECT.*|.*INSERT.*|.*UPDATE.*|.*DELETE.*"))
    .l
}
```

### Case Study 3: Race Condition Detection

```scala
// TOCTOU (Time-of-Check-Time-of-Use) pattern detection
def findTOCTOUVulnerabilities(cpg: Cpg) = {
  // Find access() calls followed by file operations
  cpg.call.name("access")
    .argument(1)
    .isIdentifier
    .referencingIdentifiers
    .inCall.name("(fopen|open)")
    .where { openCall =>
      val accessCall = openCall.argument(1).isIdentifier.inCall.name("access").head
      openCall.lineNumber.exists(ol => 
        accessCall.lineNumber.exists(al => ol > al && ol - al < 10))  // Within 10 lines
    }
    .l
}

// Shared resource access without proper locking
def findRaceConditions(cpg: Cpg) = {
  // Global variables accessed without mutex protection
  val globalVars = cpg.identifier.where(_.referencedLocal.isEmpty).name.toSet
  
  globalVars.flatMap { varName =>
    cpg.identifier.name(varName)
      .whereNot(_.method.call.name("(pthread_mutex_lock|lock|acquire).*").nonEmpty)
      .l
  }.toList
}
```

### Case Study 4: Cryptographic Vulnerability Analysis

```scala
// Find weak cryptographic practices
def findWeakCrypto(cpg: Cpg) = {
  // Weak algorithms
  val weakAlgorithms = List("MD5", "SHA1", "DES", "RC4")
  
  val weakCalls = weakAlgorithms.flatMap { algo =>
    cpg.call.name(s".*$algo.*").l
  }
  
  // Hardcoded keys/passwords
  val hardcodedSecrets = cpg.literal
    .where(_.code.length > 10)  // Reasonable key length
    .where(_.method.call.name("(encrypt|decrypt|sign|verify).*").nonEmpty)
    .l
  
  Map(
    "weak_algorithms" -> weakCalls,
    "hardcoded_secrets" -> hardcodedSecrets
  )
}

// Find improper random number usage
def findWeakRandomness(cpg: Cpg) = {
  // Use of weak PRNGs for security purposes
  cpg.call.name("(rand|srand)")
    .where(_.method.call.name("(encrypt|decrypt|key|token|password).*").nonEmpty)
    .l
}
```

### Case Study 5: Complete Project Analysis Pipeline

```scala
// File: complete_analysis.sc

def runCompleteSecurityAnalysis(cpg: Cpg) = {
  val results = scala.collection.mutable.Map[String, List[Any]]()
  
  println("Starting comprehensive security analysis...")
  
  // Memory safety issues
  results("buffer_overflows") = findBufferOverflows(cp