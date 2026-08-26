// ============================================================================
// Wisdra Extraction Payload v2.0 — WisdraExtract.java
// ============================================================================
// Usage: analyzeHeadless ... -postScript WisdraExtract.java <output> [sha256]
// ============================================================================

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.*;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.*;

public class WisdraExtract extends GhidraScript {

    private static final String WISDRA_VERSION = "2.0.0";

    private static final String[] SUSPICIOUS_APIS = {
        "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
        "NtUnmapViewOfSection", "WinExec", "ShellExecute", "CreateProcess",
        "GetProcAddress", "LoadLibrary", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "WSAStartup", "socket", "connect", "send", "recv",
        "InternetOpen", "HttpSendRequest", "URLDownloadToFile", "RegSetValue",
        "RegCreateKey", "CryptEncrypt", "CryptDecrypt"
    };

    private static final String[] ANTI_DEBUG_APIS = {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugString",
        "NtSetInformationThread", "GetTickCount", "QueryPerformanceCounter"
    };

    private static final String[] NETWORK_APIS = {
        "WSAStartup", "socket", "connect", "send", "recv",
        "InternetOpen", "InternetOpenUrl", "HttpSendRequest",
        "URLDownloadToFile", "WinHttpOpen"
    };

    // P-Code Vulnerability Hunter — dangerous function signatures
    private static final Map<String, String> DANGEROUS_FUNCTIONS = new LinkedHashMap<>();
    static {
        // Buffer overflow — unbounded copy
        DANGEROUS_FUNCTIONS.put("strcpy",   "CWE-120: Unbounded string copy — use strncpy or strlcpy");
        DANGEROUS_FUNCTIONS.put("wcscpy",   "CWE-120: Unbounded wide string copy");
        DANGEROUS_FUNCTIONS.put("lstrcpyA", "CWE-120: Unbounded string copy (Win32)");
        DANGEROUS_FUNCTIONS.put("lstrcpyW", "CWE-120: Unbounded wide string copy (Win32)");
        // Buffer overflow — unbounded concatenation
        DANGEROUS_FUNCTIONS.put("strcat",   "CWE-120: Unbounded string concatenation");
        DANGEROUS_FUNCTIONS.put("wcscat",   "CWE-120: Unbounded wide string concatenation");
        DANGEROUS_FUNCTIONS.put("lstrcatA", "CWE-120: Unbounded string concatenation (Win32)");
        // Format string
        DANGEROUS_FUNCTIONS.put("sprintf",  "CWE-134: Unbounded format string write — use snprintf");
        DANGEROUS_FUNCTIONS.put("swprintf", "CWE-134: Unbounded wide format string write");
        DANGEROUS_FUNCTIONS.put("vsprintf", "CWE-134: Unbounded variadic format string");
        // Dangerous input
        DANGEROUS_FUNCTIONS.put("gets",     "CWE-242: Banned function — no bounds checking on input");
        DANGEROUS_FUNCTIONS.put("scanf",    "CWE-120: Potentially unbounded input read");
        DANGEROUS_FUNCTIONS.put("sscanf",   "CWE-120: Potentially unbounded input parse");
        // Memory operations with size from user
        DANGEROUS_FUNCTIONS.put("memcpy",   "CWE-120: Memory copy — verify size parameter is bounded");
        DANGEROUS_FUNCTIONS.put("memmove",  "CWE-120: Memory move — verify size parameter is bounded");
        DANGEROUS_FUNCTIONS.put("RtlCopyMemory", "CWE-120: Kernel memory copy — verify bounds");
        // Command injection
        DANGEROUS_FUNCTIONS.put("system",   "CWE-78: OS command execution — potential command injection");
        DANGEROUS_FUNCTIONS.put("popen",    "CWE-78: OS command execution via pipe");
        DANGEROUS_FUNCTIONS.put("_popen",   "CWE-78: OS command execution via pipe (MSVC)");
        DANGEROUS_FUNCTIONS.put("WinExec",  "CWE-78: Win32 command execution");
        // Integer overflow targets
        DANGEROUS_FUNCTIONS.put("malloc",   "CWE-190: Verify allocation size is not user-controlled integer overflow");
        DANGEROUS_FUNCTIONS.put("calloc",   "CWE-190: Verify allocation size is not user-controlled");
        DANGEROUS_FUNCTIONS.put("realloc",  "CWE-190: Verify reallocation size is bounded");
        // Use-after-free patterns
        DANGEROUS_FUNCTIONS.put("free",     "CWE-416: Verify pointer is not used after this call");
        DANGEROUS_FUNCTIONS.put("HeapFree", "CWE-416: Verify heap pointer is not used after free");
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("[WISDRA] ERROR: No output path provided.");
            return;
        }
        String outputPath = args[0];
        String sha256 = (args.length >= 2) ? args[1] : "";

        println("[WISDRA] ═══════════════════════════════════════════════");
        println("[WISDRA]  Wisdra Extraction Engine v" + WISDRA_VERSION);
        println("[WISDRA]  P-Code Vulnerability Hunter ENABLED");
        println("[WISDRA] ═══════════════════════════════════════════════");
        println("[WISDRA] Target: " + currentProgram.getName());
        println("[WISDRA] Output: " + outputPath);

        JsonObject report = new JsonObject();

        // 1. Metadata
        println("[WISDRA] [1/7] Extracting metadata...");
        report.add("metadata", extractMetadata(sha256));

        // 2. Imports
        println("[WISDRA] [2/7] Extracting API imports...");
        JsonArray imports = extractImports();
        report.add("imports", imports);
        println("[WISDRA]        Found " + imports.size() + " imports");

        // 3-4. Sections & Entropy
        println("[WISDRA] [3/7] Analyzing PE sections & entropy...");
        JsonObject sectionData = extractSectionsAndEntropy();
        report.add("sections", sectionData.getAsJsonArray("sections"));
        report.add("entropy_analysis", sectionData.getAsJsonArray("entropy"));

        // 5. Decompilation
        println("[WISDRA] [4/7] Decompiling entry point...");
        JsonObject decomp = decompileEntry();
        report.add("decompilation", decomp);

        // 6. Strings
        println("[WISDRA] [5/7] Extracting strings...");
        JsonArray strings = extractStrings();
        report.add("strings", strings);

        // 7. P-CODE VULNERABILITY HUNT
        println("[WISDRA] [6/7] Running P-Code Vulnerability Hunter...");
        JsonArray vulns = runPCodeVulnHunter();
        report.add("vulnerabilities", vulns);
        println("[WISDRA]        Found " + vulns.size() + " potential vulnerabilities");

        // Threat Assessment (now includes vuln count)
        println("[WISDRA] [7/7] Computing threat assessment...");
        JsonObject threats = assessThreats(imports, sectionData.getAsJsonArray("entropy"), strings, vulns);
        report.add("threat_indicators", threats);

        // Write JSON
        try (FileWriter writer = new FileWriter(outputPath)) {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            gson.toJson(report, writer);
            println("[WISDRA] ═══════════════════════════════════════════════");
            println("[WISDRA]  Report written — " + vulns.size() + " vulnerabilities found");
            println("[WISDRA] ═══════════════════════════════════════════════");
        } catch (IOException e) {
            printerr("[WISDRA] ERROR writing JSON: " + e.getMessage());
        }
    }

    // =========================================================================
    // P-CODE VULNERABILITY HUNTER
    // =========================================================================

    private JsonArray runPCodeVulnHunter() {
        JsonArray vulns = new JsonArray();
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        decomp.setOptions(new DecompileOptions());

        FunctionManager funcMgr = currentProgram.getFunctionManager();
        int funcCount = 0;
        int maxFunctions = 500; // Limit to prevent timeout on huge binaries

        for (Function func : funcMgr.getFunctions(true)) {
            if (monitor.isCancelled()) break;
            if (funcCount++ > maxFunctions) break;

            DecompileResults results = decomp.decompileFunction(func, 30, monitor);
            if (results == null || !results.decompileCompleted()) continue;

            HighFunction highFunc = results.getHighFunction();
            if (highFunc == null) continue;

            // Iterate all P-Code operations in this function
            Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();
            while (ops.hasNext()) {
                PcodeOpAST op = ops.next();

                // We only care about CALL operations
                if (op.getOpcode() != PcodeOp.CALL) continue;

                // The first input varnode of a CALL is the target address
                Varnode target = op.getInput(0);
                if (target == null) continue;

                Address callAddr = target.getAddress();
                Function calledFunc = currentProgram.getFunctionManager().getFunctionAt(callAddr);
                if (calledFunc == null) continue;

                String calledName = calledFunc.getName();

                // Check if it's a dangerous function
                for (Map.Entry<String, String> entry : DANGEROUS_FUNCTIONS.entrySet()) {
                    if (calledName.equals(entry.getKey()) ||
                        calledName.equals("_" + entry.getKey()) ||
                        calledName.endsWith("::" + entry.getKey())) {

                        JsonObject vuln = new JsonObject();
                        vuln.addProperty("type", "dangerous_call");
                        vuln.addProperty("cwe", entry.getValue().split(":")[0]);
                        
                        String severity = getSeverity(entry.getKey());
                        String description = entry.getValue();

                        // --- TAINT ANALYSIS (DATA FLOW TRACKING) ---
                        // For functions taking a size or buffer (e.g., malloc, strcpy), trace the primary argument
                        if (op.getNumInputs() > 1) {
                            // By default, assume the first argument (Input 1) is the vulnerable parameter
                            // (Input 0 is the call target address)
                            int targetInputIdx = 1;
                            
                            // For some APIs, the second arg is the size (e.g. strncpy, memcpy)
                            if (calledName.contains("memcpy") || calledName.contains("memmove") || calledName.contains("strncpy")) {
                                if (op.getNumInputs() > 3) targetInputIdx = 3;
                            }

                            Varnode targetVn = op.getInput(targetInputIdx);
                            String sourceTrace = traceVarnodeSource(targetVn, 0, 10);
                            
                            if (sourceTrace.startsWith("CONSTANT")) {
                                // If it's a constant (e.g. malloc(0x100)), it's safe. Skip alerting on MEDIUM severity.
                                if ("MEDIUM".equals(severity)) {
                                    continue;
                                }
                                description += " (Data flow analysis: Target parameter is a safe CONSTANT)";
                            } else if (sourceTrace.contains("EXTERNAL_INPUT") || sourceTrace.contains("FUNCTION_RETURN")) {
                                severity = "CRITICAL";
                                description = "[CRITICAL VULNERABILITY: Untrusted Data Flow] " + description;
                                description += "\n↳ Parameter traced to untrusted source: " + sourceTrace;
                            } else {
                                description += "\n↳ Parameter origin: " + sourceTrace;
                            }
                        }
                        
                        vuln.addProperty("description", description);
                        vuln.addProperty("dangerous_function", calledName);
                        vuln.addProperty("caller_function", func.getName());
                        vuln.addProperty("caller_address", func.getEntryPoint().toString());
                        vuln.addProperty("call_address", op.getSeqnum().getTarget().toString());
                        vuln.addProperty("severity", severity);

                        // Try to get decompiled line for context
                        try {
                            String cCode = results.getDecompiledFunction().getC();
                            String contextLine = findRelevantLine(cCode, calledName);
                            vuln.addProperty("code_context", contextLine);
                        } catch (Exception e) {
                            vuln.addProperty("code_context", "// context unavailable");
                        }

                        vulns.add(vuln);
                        break; // Don't double-flag same call
                    }
                }
            }

            // Detect potential integer overflow before allocation
            scanForIntOverflowPattern(highFunc, func, vulns);
        }

        decomp.dispose();
        return vulns;
    }

    private void scanForIntOverflowPattern(HighFunction hf, Function func, JsonArray vulns) {
        Iterator<PcodeOpAST> ops = hf.getPcodeOps();
        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();
            // Look for INT_MULT followed by CALL to malloc/calloc
            if (op.getOpcode() == PcodeOp.INT_MULT) {
                // Check if any output of this multiply feeds into a CALL
                Varnode output = op.getOutput();
                if (output == null) continue;

                Iterator<PcodeOp> descendants = output.getDescendants();
                while (descendants.hasNext()) {
                    PcodeOp desc = descendants.next();
                    if (desc.getOpcode() == PcodeOp.CALL) {
                        Varnode callTarget = desc.getInput(0);
                        if (callTarget == null) continue;
                        Function calledFunc = currentProgram.getFunctionManager()
                            .getFunctionAt(callTarget.getAddress());
                        if (calledFunc == null) continue;
                        String name = calledFunc.getName();
                        if (name.contains("malloc") || name.contains("calloc") ||
                            name.contains("alloc") || name.contains("realloc")) {
                            JsonObject vuln = new JsonObject();
                            vuln.addProperty("type", "integer_overflow_alloc");
                            vuln.addProperty("cwe", "CWE-190");
                            vuln.addProperty("description",
                                "CWE-190: Integer multiplication flows directly into " + name +
                                " — potential heap overflow if inputs are attacker-controlled");
                            vuln.addProperty("dangerous_function", name);
                            vuln.addProperty("caller_function", func.getName());
                            vuln.addProperty("caller_address", func.getEntryPoint().toString());
                            vuln.addProperty("call_address", op.getSeqnum().getTarget().toString());
                            vuln.addProperty("severity", "CRITICAL");
                            vuln.addProperty("code_context", "// INT_MULT -> " + name + "()");
                            vulns.add(vuln);
                        }
                    }
                }
            }
        }
    }

    /**
     * Recursively traces a Varnode backward through the P-Code AST to determine its source.
     */
    private String traceVarnodeSource(Varnode vn, int depth, int maxDepth) {
        if (vn == null) return "UNKNOWN";
        if (depth > maxDepth) return "MAX_DEPTH_REACHED";

        if (vn.isConstant()) {
            return "CONSTANT(0x" + Long.toHexString(vn.getOffset()) + ")";
        }

        PcodeOp defOp = vn.getDef();
        
        if (defOp == null) {
            if (vn.isRegister()) return "EXTERNAL_INPUT(Register)";
            if (vn.isAddress()) return "EXTERNAL_INPUT(Memory)";
            return "EXTERNAL_INPUT(Unknown)";
        }

        int opcode = defOp.getOpcode();
        switch (opcode) {
            case PcodeOp.COPY:
            case PcodeOp.CAST:
                return traceVarnodeSource(defOp.getInput(0), depth + 1, maxDepth);
                
            case PcodeOp.LOAD:
                return "MEMORY_LOAD_FROM: [" + traceVarnodeSource(defOp.getInput(1), depth + 1, maxDepth) + "]";
                
            case PcodeOp.CALL:
                Varnode callTarget = defOp.getInput(0);
                if (callTarget != null) {
                    Function func = currentProgram.getFunctionManager().getFunctionAt(callTarget.getAddress());
                    String funcName = (func != null) ? func.getName() : callTarget.getAddress().toString();
                    return "FUNCTION_RETURN(" + funcName + ")";
                }
                return "FUNCTION_RETURN(Unknown)";
                
            case PcodeOp.PTRSUB:
            case PcodeOp.PTRADD:
            case PcodeOp.INT_ADD:
            case PcodeOp.INT_SUB:
            case PcodeOp.INT_MULT:
                String op1 = traceVarnodeSource(defOp.getInput(0), depth + 1, maxDepth);
                String op2 = traceVarnodeSource(defOp.getInput(1), depth + 1, maxDepth);
                return "COMPUTED_MATH(" + op1 + " op " + op2 + ")";

            case PcodeOp.MULTIEQUAL:
                return "PHI_NODE_BRANCH";

            default:
                return "OPCODE_" + defOp.getMnemonic();
        }
    }

    private String getSeverity(String funcName) {
        // Critical: banned functions, command injection
        if ("gets strcpy strcat sprintf vsprintf system popen WinExec".contains(funcName))
            return "CRITICAL";
        // High: unbounded operations
        if ("memcpy memmove wcscpy wcscat scanf sscanf".contains(funcName))
            return "HIGH";
        // Medium: allocation/free patterns
        if ("malloc calloc realloc free HeapFree".contains(funcName))
            return "MEDIUM";
        return "LOW";
    }

    private String findRelevantLine(String cCode, String funcName) {
        for (String line : cCode.split("\n")) {
            if (line.contains(funcName + "(") || line.contains(funcName + " (")) {
                return line.trim();
            }
        }
        return "// " + funcName + "() call detected";
    }

    // =========================================================================
    // EXISTING EXTRACTION METHODS (upgraded)
    // =========================================================================

    private JsonObject extractMetadata(String sha256) {
        JsonObject meta = new JsonObject();
        meta.addProperty("file_name", currentProgram.getName());
        meta.addProperty("file_format", currentProgram.getExecutableFormat());
        meta.addProperty("architecture", currentProgram.getLanguage().getLanguageID().getIdAsString());

        try {
            meta.addProperty("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
        } catch (Exception e) {
            meta.addProperty("compiler", "unknown");
        }

        String entry = "unknown";
        SymbolIterator syms = currentProgram.getSymbolTable().getSymbols("entry");
        if (syms.hasNext()) {
            entry = syms.next().getAddress().toString();
        } else {
            Address eAddr = currentProgram.getMinAddress();
            if (eAddr != null) entry = eAddr.toString();
        }

        meta.addProperty("entry_point", entry);
        meta.addProperty("image_base", currentProgram.getImageBase().toString());
        meta.addProperty("sha256", sha256);

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        meta.addProperty("analysis_date", sdf.format(new Date()));
        meta.addProperty("wisdra_version", WISDRA_VERSION);

        return meta;
    }

    private JsonArray extractImports() {
        JsonArray imports = new JsonArray();
        SymbolIterator extSymbols = currentProgram.getSymbolTable().getExternalSymbols();

        while (extSymbols.hasNext()) {
            Symbol sym = extSymbols.next();
            if (sym.getSymbolType() == SymbolType.FUNCTION) {
                String funcName = sym.getName();
                String addr = sym.getAddress().toString();
                String library = "unknown";
                if (sym.getParentNamespace() != null) {
                    library = sym.getParentNamespace().getName();
                }

                JsonObject obj = new JsonObject();
                obj.addProperty("library", library);
                obj.addProperty("function", funcName);
                obj.addProperty("address", addr);
                obj.addProperty("category", categorizeApi(funcName));
                imports.add(obj);
            }
        }
        return imports;
    }

    private JsonObject extractSectionsAndEntropy() throws Exception {
        JsonArray sections = new JsonArray();
        JsonArray entropyArr = new JsonArray();
        Memory memory = currentProgram.getMemory();

        for (MemoryBlock block : memory.getBlocks()) {
            String name = block.getName();
            long size = block.getSize();

            String perms = "";
            if (block.isRead()) perms += "R";
            if (block.isWrite()) perms += "W";
            if (block.isExecute()) perms += "X";

            JsonObject secObj = new JsonObject();
            secObj.addProperty("name", name);
            secObj.addProperty("virtual_address", block.getStart().toString());
            secObj.addProperty("virtual_size", size);
            secObj.addProperty("raw_size", size);
            secObj.addProperty("permissions", perms);
            sections.add(secObj);

            if (block.isInitialized()) {
                int readSize = (int) Math.min(size, 1024 * 1024);
                byte[] data = new byte[readSize];
                try {
                    block.getBytes(block.getStart(), data);
                    double ent = calculateEntropy(data);

                    JsonObject entObj = new JsonObject();
                    entObj.addProperty("section", name);
                    entObj.addProperty("entropy", Math.round(ent * 10000.0) / 10000.0);
                    entObj.addProperty("suspicious", ent > 7.0);
                    entObj.addProperty("verdict", entropyVerdict(ent));
                    entropyArr.add(entObj);
                } catch (Exception e) { /* skip */ }
            }
        }

        JsonObject result = new JsonObject();
        result.add("sections", sections);
        result.add("entropy", entropyArr);
        return result;
    }

    private JsonObject decompileEntry() {
        JsonObject result = new JsonObject();
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        decomp.setOptions(new DecompileOptions());

        FunctionManager funcManager = currentProgram.getFunctionManager();
        Function entryFunc = null;

        String[] entryNames = {"main", "_main", "entry", "_start", "WinMain", "DllMain"};
        for (String name : entryNames) {
            for (Function f : funcManager.getFunctions(true)) {
                if (f.getName().equals(name)) { entryFunc = f; break; }
            }
            if (entryFunc != null) break;
        }

        if (entryFunc == null) {
            SymbolIterator syms = currentProgram.getSymbolTable().getSymbols("entry");
            if (syms.hasNext()) entryFunc = funcManager.getFunctionAt(syms.next().getAddress());
        }

        if (entryFunc == null) {
            FunctionIterator iter = funcManager.getFunctions(true);
            if (iter.hasNext()) entryFunc = iter.next();
        }

        if (entryFunc != null) {
            DecompileResults dr = decomp.decompileFunction(entryFunc, 60, monitor);
            if (dr != null && dr.decompileCompleted()) {
                String code = dr.getDecompiledFunction().getC();
                result.addProperty("name", entryFunc.getName());
                result.addProperty("address", entryFunc.getEntryPoint().toString());
                result.addProperty("code", code);
                result.addProperty("line_count", code.split("\n").length);
                decomp.dispose();
                return result;
            }
        }

        decomp.dispose();
        result.addProperty("name", "unknown");
        result.addProperty("address", "0x0");
        result.addProperty("code", "// Decompilation failed");
        result.addProperty("line_count", 1);
        return result;
    }

    private JsonArray extractStrings() {
        JsonArray strings = new JsonArray();
        Listing listing = currentProgram.getListing();
        DataIterator dataIter = listing.getDefinedData(true);
        int count = 0;

        while (dataIter.hasNext() && count < 100) {
            Data data = dataIter.next();
            if (data.getDataType() != null && data.getDataType().getName().toLowerCase().contains("string")) {
                Object val = data.getValue();
                if (val instanceof String) {
                    String str = (String) val;
                    if (str.length() >= 6 && !str.trim().isEmpty()) {
                        strings.add(str);
                        count++;
                    }
                }
            }
        }
        return strings;
    }

    private JsonObject assessThreats(JsonArray imports, JsonArray entropy, JsonArray strings, JsonArray vulns) {
        List<String> suspiciousList = new ArrayList<>();
        List<String> antiDebugList = new ArrayList<>();
        List<String> networkList = new ArrayList<>();

        for (int i = 0; i < imports.size(); i++) {
            String func = imports.get(i).getAsJsonObject().get("function").getAsString();
            if (isSuspicious(func)) suspiciousList.add(func);
            for (String ad : ANTI_DEBUG_APIS) if (func.contains(ad) && !antiDebugList.contains(func)) antiDebugList.add(func);
            for (String net : NETWORK_APIS) if (func.contains(net) && !networkList.contains(func)) networkList.add(func);
        }

        boolean packing = false;
        for (int i = 0; i < entropy.size(); i++) {
            JsonObject ent = entropy.get(i).getAsJsonObject();
            if (ent.get("entropy").getAsDouble() > 7.2 &&
               (ent.get("section").getAsString().contains(".text") || ent.get("section").getAsString().contains("CODE"))) {
                packing = true; break;
            }
        }

        // Count critical vulns
        int criticalVulns = 0;
        int highVulns = 0;
        for (int i = 0; i < vulns.size(); i++) {
            String sev = vulns.get(i).getAsJsonObject().get("severity").getAsString();
            if ("CRITICAL".equals(sev)) criticalVulns++;
            else if ("HIGH".equals(sev)) highVulns++;
        }

        int score = 0;
        score += Math.min(suspiciousList.size() * 5, 40);
        score += antiDebugList.size() * 10;
        if (packing) score += 20;
        score += Math.min(networkList.size() * 5, 20);
        score += criticalVulns * 8;
        score += highVulns * 4;
        score = Math.min(score, 100);

        String label = "CLEAN";
        if (score >= 75) label = "CRITICAL";
        else if (score >= 50) label = "HIGH";
        else if (score >= 25) label = "MODERATE";
        else if (score > 0) label = "LOW";

        JsonObject threats = new JsonObject();
        JsonArray susArr = new JsonArray(); for (String s : suspiciousList) susArr.add(s);
        threats.add("suspicious_imports", susArr);
        JsonArray adArr = new JsonArray(); for (String s : antiDebugList) adArr.add(s);
        threats.add("anti_debug", adArr);
        JsonArray netArr = new JsonArray(); for (String s : networkList) netArr.add(s);
        threats.add("network_indicators", netArr);
        threats.addProperty("packing_detected", packing);
        threats.addProperty("vulnerability_count", vulns.size());
        threats.addProperty("critical_vulns", criticalVulns);
        threats.addProperty("risk_score", score);
        threats.addProperty("risk_label", label);

        return threats;
    }

    // --- Helpers ---

    private double calculateEntropy(byte[] data) {
        if (data == null || data.length == 0) return 0.0;
        int[] counts = new int[256];
        for (byte b : data) counts[b & 0xFF]++;
        double entropy = 0.0;
        double len = data.length;
        for (int count : counts) {
            if (count > 0) { double p = count / len; entropy -= p * (Math.log(p) / Math.log(2)); }
        }
        return entropy;
    }

    private String entropyVerdict(double ent) {
        if (ent > 7.5) return "CRITICAL — likely encrypted/compressed";
        if (ent > 7.0) return "HIGH — possibly packed";
        if (ent > 6.0) return "ELEVATED — unusual density";
        if (ent > 4.0) return "NORMAL — standard code/data";
        return "LOW — sparse data";
    }

    private String categorizeApi(String func) {
        if (func.contains("Alloc") || func.contains("Protect")) return "memory";
        if (func.contains("WriteProcessMemory") || func.contains("RemoteThread")) return "injection";
        if (func.contains("LoadLibrary") || func.contains("GetProcAddress")) return "dynamic_load";
        if (func.contains("Execute") || func.contains("CreateProcess")) return "execution";
        if (func.contains("Debugger") || func.contains("QueryInformationProcess")) return "anti_debug";
        if (func.contains("WSA") || func.contains("Internet") || func.contains("socket")) return "network";
        if (func.contains("RegCreate") || func.contains("RegSet")) return "registry";
        if (func.contains("Crypt")) return "crypto";
        return "";
    }

    private boolean isSuspicious(String func) {
        for (String s : SUSPICIOUS_APIS) { if (func.contains(s)) return true; }
        return false;
    }
}
