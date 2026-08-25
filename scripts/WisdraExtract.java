// ============================================================================
// Wisdra Extraction Payload — WisdraExtract.java
// ============================================================================
// This script runs natively inside Ghidra's headless environment.
// It is invoked via: analyzeHeadless ... -postScript WisdraExtract.java <output>
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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Data;
import ghidra.program.model.address.Address;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;

public class WisdraExtract extends GhidraScript {

    private static final String WISDRA_VERSION = "0.1.0";
    
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

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("[WISDRA] ERROR: No output path provided.");
            return;
        }
        String outputPath = args[0];

        println("[WISDRA] ═══════════════════════════════════════════════");
        println("[WISDRA]  Wisdra Extraction Engine v" + WISDRA_VERSION);
        println("[WISDRA] ═══════════════════════════════════════════════");
        println("[WISDRA] Target: " + currentProgram.getName());
        println("[WISDRA] Output: " + outputPath);

        JsonObject report = new JsonObject();

        // 1. Metadata
        println("[WISDRA] [1/6] Extracting metadata...");
        report.add("metadata", extractMetadata());

        // 2. Imports
        println("[WISDRA] [2/6] Extracting API imports...");
        JsonArray imports = extractImports();
        report.add("imports", imports);
        println("[WISDRA]        Found " + imports.size() + " imports");

        // 3. Sections & 4. Entropy
        println("[WISDRA] [3/6 & 4/6] Analyzing PE sections & entropy...");
        JsonObject sectionData = extractSectionsAndEntropy();
        report.add("sections", sectionData.getAsJsonArray("sections"));
        report.add("entropy_analysis", sectionData.getAsJsonArray("entropy"));

        // 5. Decompilation
        println("[WISDRA] [5/6] Decompiling entry point...");
        JsonObject decomp = decompileEntry();
        report.add("decompilation", decomp);

        // 6. Strings
        println("[WISDRA] [6/6] Extracting strings...");
        JsonArray strings = extractStrings();
        report.add("strings", strings);

        // Threat Assessment
        println("[WISDRA] Assessing threats...");
        JsonObject threats = assessThreats(imports, sectionData.getAsJsonArray("entropy"), strings);
        report.add("threat_indicators", threats);

        // Write JSON
        try (FileWriter writer = new FileWriter(outputPath)) {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            gson.toJson(report, writer);
            println("[WISDRA] ═══════════════════════════════════════════════");
            println("[WISDRA]  Report written successfully!");
            println("[WISDRA] ═══════════════════════════════════════════════");
        } catch (IOException e) {
            printerr("[WISDRA] ERROR writing JSON: " + e.getMessage());
        }
    }

    private JsonObject extractMetadata() {
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
            Address eAddr = currentProgram.getMinAddress(); // Fallback
            if (eAddr != null) entry = eAddr.toString();
        }
        
        meta.addProperty("entry_point", entry);
        meta.addProperty("image_base", currentProgram.getImageBase().toString());
        meta.addProperty("sha256", "");
        
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
                } catch (Exception e) {
                    // Ignore memory read errors
                }
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
                if (f.getName().equals(name)) {
                    entryFunc = f;
                    break;
                }
            }
            if (entryFunc != null) break;
        }

        if (entryFunc == null) {
            SymbolIterator syms = currentProgram.getSymbolTable().getSymbols("entry");
            if (syms.hasNext()) {
                entryFunc = funcManager.getFunctionAt(syms.next().getAddress());
            }
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
                return result;
            }
        }

        result.addProperty("name", "unknown");
        result.addProperty("address", "0x0");
        result.addProperty("code", "// Decompilation failed");
        result.addProperty("line_count", 1);
        return result;
    }

    private JsonArray extractStrings() {
        JsonArray strings = new JsonArray();
        Listing listing = currentProgram.getListing();
        ghidra.program.model.listing.DataIterator dataIter = listing.getDefinedData(true);
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

    private JsonObject assessThreats(JsonArray imports, JsonArray entropy, JsonArray strings) {
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
                packing = true;
                break;
            }
        }

        int score = 0;
        score += Math.min(suspiciousList.size() * 5, 40);
        score += antiDebugList.size() * 10;
        if (packing) score += 20;
        score += Math.min(networkList.size() * 5, 20);
        score = Math.min(score, 100);

        String label = "CLEAN";
        if (score >= 75) label = "CRITICAL";
        else if (score >= 50) label = "HIGH";
        else if (score >= 25) label = "MODERATE";
        else if (score > 0) label = "LOW";

        JsonObject threats = new JsonObject();
        JsonArray susArr = new JsonArray();
        for (String s : suspiciousList) susArr.add(s);
        threats.add("suspicious_imports", susArr);
        
        JsonArray adArr = new JsonArray();
        for (String s : antiDebugList) adArr.add(s);
        threats.add("anti_debug", adArr);
        
        JsonArray netArr = new JsonArray();
        for (String s : networkList) netArr.add(s);
        threats.add("network_indicators", netArr);
        
        threats.addProperty("packing_detected", packing);
        threats.addProperty("risk_score", score);
        threats.addProperty("risk_label", label);

        return threats;
    }

    // --- Math & String Helpers ---

    private double calculateEntropy(byte[] data) {
        if (data == null || data.length == 0) return 0.0;
        int[] counts = new int[256];
        for (byte b : data) {
            counts[b & 0xFF]++;
        }
        double entropy = 0.0;
        double len = data.length;
        for (int count : counts) {
            if (count > 0) {
                double p = count / len;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
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
        for (String s : SUSPICIOUS_APIS) {
            if (func.contains(s)) return true;
        }
        return false;
    }
}
