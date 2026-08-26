# WISDRA AUTOMATED BINARY ANALYSIS REPORT
=========================================

## 1. TARGET METADATA
- **File Name:** notepad.exe
- **SHA-256:** DUMMY_SHA256

## 2. THREAT ASSESSMENT
- **Overall Risk Level:** CRITICAL (Score: 100)
- **Total Vulnerabilities Detected:** 11
- **Critical Vulnerabilities:** 2
- **Packing Verdict:** NOT DETECTED (Normal Entropy)

## 3. SUSPICIOUS API HEURISTICS
### `<anti_debug>` Capabilities
- `IsDebuggerPresent`
- `OutputDebugStringW`
- `QueryPerformanceCounter`

### `<suspicious>` / General Malicious Operations
- `GetProcAddress`
- `CreateProcessW`
- `RegCreateKeyExW`
- `RegSetValueExW`
- `RegCreateKeyW`
- `ShellExecuteW`


## 4. VULNERABILITY INTELLIGENCE (P-CODE ANALYSIS)
| CWE | Severity | Function | Caller Address | Context |
|-----|----------|----------|----------------|---------|
| CWE-120 | CRITICAL | `memmove` | `14000717c` | `memmove((void *)(uVar14 + (longlong)local_88),local_88,_Size);` |
| CWE-120 | CRITICAL | `memcpy` | `1400096fc` | `memcpy(param_1,param_3,param_4);` |
| CWE-120 | HIGH | `memcpy` | `140009e44` | `memcpy(_Dst,param_2,_Size);` |
| CWE-120 | HIGH | `memcpy` | `14000be08` | `memcpy(_Dst,param_2,_Size);` |
| CWE-120 | HIGH | `memcpy` | `140010f48` | `memcpy(lpWideCharStr,psVar10,(longlong)wParam * 2);` |
| CWE-120 | HIGH | `memcpy` | `14001eaf4` | `memcpy(param_4,param_3,lVar2 * 2);` |
| CWE-120 | HIGH | `memcpy` | `14001f948` | `memcpy(&DAT_140036540,(void *)((longlong)pvVar3 + (ulonglong)local_res10[0] * 2),` |
| CWE-120 | HIGH | `memcpy` | `14002193c` | `memcpy(_Dst_00,param_1,sVar2);` |
| CWE-120 | HIGH | `memcpy` | `14002193c` | `memcpy(_Dst_00,param_1,sVar2);` |
| CWE-120 | HIGH | `memcpy` | `14002193c` | `memcpy(_Dst_00,param_1,sVar2);` |
| CWE-120 | HIGH | `memcpy` | `140024420` | `memcpy(param_2,param_1,uVar5 * 2);` |

### Detailed Vulnerability Analysis
#### 1. CWE-120 in `memmove`
- **Type:** dangerous_call
- **Severity:** CRITICAL
- **Caller:** FUN_14000717c at `14000717c`
- **Call Site:** `140007496`
- **Context:**
```c
memmove((void *)(uVar14 + (longlong)local_88),local_88,_Size);
```
- **Description:**
[CRITICAL VULNERABILITY: Untrusted Data Flow] CWE-120: Memory move — verify size parameter is bounded
↳ Parameter traced to untrusted source: COMPUTED_MATH(MEMORY_LOAD_FROM: [COMPUTED_MATH(EXTERNAL_INPUT(Register) op CONSTANT(0x20))] op PHI_NODE_BRANCH)

#### 2. CWE-120 in `memcpy`
- **Type:** dangerous_call
- **Severity:** CRITICAL
- **Caller:** FUN_1400096fc at `1400096fc`
- **Call Site:** `14000974e`
- **Context:**
```c
memcpy(param_1,param_3,param_4);
```
- **Description:**
[CRITICAL VULNERABILITY: Untrusted Data Flow] CWE-120: Memory copy — verify size parameter is bounded
↳ Parameter traced to untrusted source: EXTERNAL_INPUT(Register)

#### 3. CWE-120 in `memcpy`
- **Type:** dangerous_call
- **Severity:** HIGH
- **Caller:** FUN_140009e44 at `140009e44`
- **Call Site:** `140009ef0`
- **Context:**
```c
memcpy(_Dst,param_2,_Size);
```
- **Description:**
CWE-120: Memory copy — verify size parameter is bounded
↳ Parameter origin: COMPUTED_MATH(PHI_NODE_BRANCH op CONSTANT(0x2))

#### 4. CWE-120 in `memcpy`
- **Type:** dangerous_call
- **Severity:** HIGH
- **Caller:** FUN_14000be08 at `14000be08`
- **Call Site:** `14000beb6`
- **Context:**
```c
memcpy(_Dst,param_2,_Size);
```
- **Description:**
CWE-120: Memory copy — verify size parameter is bounded
↳ Parameter origin: COMPUTED_MATH(PHI_NODE_BRANCH op CONSTANT(0x2))

#### 5. CWE-120 in `memcpy`
- **Type:** dangerous_call
- **Severity:** HIGH
- **Caller:** FUN_140010f48 at `140010f48`
- **Call Site:** `1400114f3`
- **Context:**
```c
memcpy(lpWideCharStr,psVar10,(longlong)wParam * 2);
```
- **Description:**
CWE-120: Memory copy — verify size parameter is bounded
↳ Parameter origin: COMPUTED_MATH(PHI_NODE_BRANCH op CONSTANT(0x2))

#### 6. CWE-120 in `memcpy`
- **Type:** dangerous_call
- **Severity:** HIGH
- **Caller:** FUN_14001eaf4 at `14001eaf4`
- **Call Site:** `14001eb5f`
- **Context:**
```c
memcpy(param_4,param_3,lVar2 * 2);
```
- **Description:**
CWE-120: Memory copy — verify size parameter is bounded
↳ Parameter origin: COMPUTED_MATH(OPCODE_INT_SEXT op CONSTANT(0x2))

#### 7. CWE-120 in `memcpy`
- **Type:** dangerous_call
- **Severity:** HIGH
- **Caller:** FUN_14001f948 at `14001f948`
- **Call Site:** `14001f9f5`
- **Context:**
```c
memcpy(&DAT_140036540,(void *)((longlong)pvVar3 + (ulonglong)local_res10[0] * 2),
```
- **Description:**
CWE-120: Memory copy — verify size parameter is bounded
↳ Parameter origin: COMPUTED_MATH(OPCODE_INT_ZEXT op CONSTANT(0x2))

#### 8. CWE-120 in `memcpy`
- **Type:** dangerous_call
- **Severity:** HIGH
- **Caller:** FUN_14002193c at `14002193c`
- **Call Site:** `140021a38`
- **Context:**
```c
memcpy(_Dst_00,param_1,sVar2);
```
- **Description:**
CWE-120: Memory copy — verify size parameter is bounded
↳ Parameter origin: COMPUTED_MATH(OPCODE_INT_SRIGHT op CONSTANT(0x2))

#### 9. CWE-120 in `memcpy`
- **Type:** dangerous_call
- **Severity:** HIGH
- **Caller:** FUN_14002193c at `14002193c`
- **Call Site:** `140021a4d`
- **Context:**
```c
memcpy(_Dst_00,param_1,sVar2);
```
- **Description:**
CWE-120: Memory copy — verify size parameter is bounded
↳ Parameter origin: COMPUTED_MATH(OPCODE_INT_SEXT op CONSTANT(0x2))

#### 10. CWE-120 in `memcpy`
- **Type:** dangerous_call
- **Severity:** HIGH
- **Caller:** FUN_14002193c at `14002193c`
- **Call Site:** `140021a96`
- **Context:**
```c
memcpy(_Dst_00,param_1,sVar2);
```
- **Description:**
CWE-120: Memory copy — verify size parameter is bounded
↳ Parameter origin: COMPUTED_MATH(OPCODE_INT_SEXT op COMPUTED_MATH(OPCODE_INT_SRIGHT op CONSTANT(0xfffffffffffffffe)))

#### 11. CWE-120 in `memcpy`
- **Type:** dangerous_call
- **Severity:** HIGH
- **Caller:** FUN_140024420 at `140024420`
- **Call Site:** `1400244d5`
- **Context:**
```c
memcpy(param_2,param_1,uVar5 * 2);
```
- **Description:**
CWE-120: Memory copy — verify size parameter is bounded
↳ Parameter origin: COMPUTED_MATH(COMPUTED_MATH(PHI_NODE_BRANCH op CONSTANT(0x1)) op CONSTANT(0x2))


## 5. MITRE ATT&CK MAPPINGS
| Tactic | Technique | ID |
|--------|-----------|----|
| Defense Evasion | Debugger Evasion | T1622 |
| Persistence | Registry Run Keys / Startup Folder | T1547.001 |
| Defense Evasion | Modify Registry | T1112 |
| Defense Evasion | Exploitation for Defense Evasion | T1211 |
| Privilege Escalation | Exploitation for Privilege Escalation | T1068 |

## 6. GENERATED YARA RULE
```yara
rule notepad_exe {
    meta:
        author = "Wisdra Automated Engine"
        description = "Auto-generated rule for notepad.exe"
        date = "2026-08-26T09:03:26Z"
        risk_level = "CRITICAL"
    strings:
        $api_0 = "GetProcAddress" ascii wide
        $api_1 = "CreateProcessW" ascii wide
        $api_2 = "IsDebuggerPresent" ascii wide
        $api_3 = "RegCreateKeyExW" ascii wide
        $api_4 = "RegSetValueExW" ascii wide
        $api_5 = "RegCreateKeyW" ascii wide
        $api_6 = "ShellExecuteW" ascii wide
        $api_7 = "OutputDebugStringW" ascii wide
        $api_8 = "QueryPerformanceCounter" ascii wide
        $str_9 = "Unknown exception" ascii wide
        $str_10 = "bad allocation" ascii wide
        $str_11 = "bad array new length" ascii wide
        $str_12 = "ADVAPI32.dll" ascii wide
        $str_13 = "COMDLG32.dll" ascii wide
        $str_14 = "PROPSYS.dll" ascii wide
        $str_15 = "SHELL32.dll" ascii wide
        $str_16 = "WINSPOOL.DRV" ascii wide
        $str_17 = "urlmon.dll" ascii wide
        $str_18 = "Exception" ascii wide
    condition:
        uint16(0) == 0x5A4D
        and (
            9 of them
        )
}

```
---
*Report automatically generated by Wisdra V2 Core.*
