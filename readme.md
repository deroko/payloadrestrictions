# PayloadRestrictions

PayloadRestrictions is the new name under which EMET is integrated into Windows 10 Insider. In the past EMET was delivered via the SHIM database and was called EMET.dll, but now its functionality is replaced by PayloadRestrictions.dll. This DLL is not anymore injected into a process via SHIM but in another way which is more tightly integrated into Windows.


This tighter integration can be spotted by looking at the new mitigation flags in the EPROCESS structure:

```
+0x828 MitigationFlagsValues : <unnamed-tag>
   +0x000 ControlFlowGuardEnabled : Pos 0, 1 Bit
   +0x000 ControlFlowGuardExportSuppressionEnabled : Pos 1, 1 Bit
   +0x000 ControlFlowGuardStrict : Pos 2, 1 Bit
   +0x000 DisallowStrippedImages : Pos 3, 1 Bit
   +0x000 ForceRelocateImages : Pos 4, 1 Bit
   +0x000 HighEntropyASLREnabled : Pos 5, 1 Bit
   +0x000 StackRandomizationDisabled : Pos 6, 1 Bit
   +0x000 ExtensionPointDisable : Pos 7, 1 Bit
   +0x000 DisableDynamicCode : Pos 8, 1 Bit
   +0x000 DisableDynamicCodeAllowOptOut : Pos 9, 1 Bit
   +0x000 DisableDynamicCodeAllowRemoteDowngrade : Pos 10, 1 Bit
   +0x000 AuditDisableDynamicCode : Pos 11, 1 Bit
   +0x000 DisallowWin32kSystemCalls : Pos 12, 1 Bit
   +0x000 AuditDisallowWin32kSystemCalls : Pos 13, 1 Bit
   +0x000 EnableFilteredWin32kAPIs : Pos 14, 1 Bit
   +0x000 AuditFilteredWin32kAPIs : Pos 15, 1 Bit
   +0x000 DisableNonSystemFonts : Pos 16, 1 Bit
   +0x000 AuditNonSystemFontLoading : Pos 17, 1 Bit
   +0x000 PreferSystem32Images : Pos 18, 1 Bit
   +0x000 ProhibitRemoteImageMap : Pos 19, 1 Bit
   +0x000 AuditProhibitRemoteImageMap : Pos 20, 1 Bit
   +0x000 ProhibitLowILImageMap : Pos 21, 1 Bit
   +0x000 AuditProhibitLowILImageMap : Pos 22, 1 Bit
   +0x000 SignatureMitigationOptIn : Pos 23, 1 Bit
   +0x000 AuditBlockNonMicrosoftBinaries : Pos 24, 1 Bit
   +0x000 AuditBlockNonMicrosoftBinariesAllowStore : Pos 25, 1 Bit
   +0x000 LoaderIntegrityContinuityEnabled : Pos 26, 1 Bit
   +0x000 AuditLoaderIntegrityContinuity : Pos 27, 1 Bit
   +0x000 EnableModuleTamperingProtection : Pos 28, 1 Bit
   +0x000 EnableModuleTamperingProtectionNoInherit : Pos 29, 1 Bit
+0x82c MitigationFlags2 : Uint4B
+0x82c MitigationFlags2Values : <unnamed-tag>
   +0x000 EnableExportAddressFilter : Pos 0, 1 Bit
   +0x000 AuditExportAddressFilter : Pos 1, 1 Bit
   +0x000 EnableExportAddressFilterPlus : Pos 2, 1 Bit
   +0x000 AuditExportAddressFilterPlus : Pos 3, 1 Bit
   +0x000 EnableRopStackPivot : Pos 4, 1 Bit
   +0x000 AuditRopStackPivot : Pos 5, 1 Bit
   +0x000 EnableRopCallerCheck : Pos 6, 1 Bit
   +0x000 AuditRopCallerCheck : Pos 7, 1 Bit
   +0x000 EnableRopSimExec : Pos 8, 1 Bit
   +0x000 AuditRopSimExec  : Pos 9, 1 Bit
   +0x000 EnableImportAddressFilter : Pos 10, 1 Bit
   +0x000 AuditImportAddressFilter : Pos 11, 1 Bit
   ```

But how is the PayloadRestrictions DLL loaded into a process?

First we have to look into ntoskrnl.exe.

From **PsAllocateProcess** we may see 2 functions being called:

```
PAGE:00000001404E0FFF                 lea     rdx, [rsp+488h+var_198]
PAGE:00000001404E1007                 mov     rcx, r13
PAGE:00000001404E100A                 call    PspReadIFEOMitigationOptions
PAGE:00000001404E100F                 movaps  xmm0, [rsp+488h+var_198]
PAGE:00000001404E1017                 movdqa  [rsp+488h+var_2A8], xmm0
PAGE:00000001404E1020                 movups  xmm0, cs:PspSystemMitigationOptions
PAGE:00000001404E1027                 movups  [rsp+488h+var_298], xmm0
PAGE:00000001404E102F                 lea     r8, [rsp+488h+var_198]
PAGE:00000001404E1037                 lea     rdx, [rsp+488h+var_2A8]
PAGE:00000001404E103F                 lea     rcx, [rsp+488h+var_298]
PAGE:00000001404E1047                 call    PspInheritMitigationOptions
PAGE:00000001404E104C                 xor     eax, eax
PAGE:00000001404E104E                 mov     qword ptr [rsp+488h+var_318], rax
PAGE:00000001404E1056                 mov     qword ptr [rsp+488h+var_318+8], rax
PAGE:00000001404E105E                 lea     rdx, [rsp+488h+var_318]
PAGE:00000001404E1066                 mov     rcx, r13
PAGE:00000001404E1069                 call    PspReadIFEOMitigationAuditOptions
PAGE:00000001404E106E                 movaps  xmm0, [rsp+488h+var_318]
PAGE:00000001404E1076                 movdqa  [rsp+488h+var_288], xmm0
PAGE:00000001404E107F                 movups  xmm0, cs:PspSystemMitigationAuditOptions
PAGE:00000001404E1086                 movups  [rsp+488h+var_278], xmm0
PAGE:00000001404E108E                 lea     r8, [rsp+488h+var_318]
PAGE:00000001404E1096                 lea     rdx, [rsp+488h+var_288]
PAGE:00000001404E109E                 lea     rcx, [rsp+488h+var_278]
PAGE:00000001404E10A6                 call    PspInheritMitigationAuditOptions
```

The 2 functions which we are interested into are **PspReadIFEOMitigationAuditOptions** and **PspReadIFEOMitigationOptions**. These functions will read the **Image File Execution Options** from the registry key  **HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options**. These mitigations can be set through **Windows Defender** by going to "App & Browser control -> Exploit Protection Settings -> Program settings". From there it's possible to set various mitigation options which will be encoded inside of **Image File Execution Options** as two binary values **MitigationOptions** and **MitigationAuditOptions** which are stored under the above mentioned key.

As already mentioned by https://twitter.com/ivanlef0u/status/895610764521766913 EMET is implemented as **PayloadRestrictions.dll** which is loaded into a process via the verifier.dll. This task is performed by the following code in verifier.dll:

```
.text:000000018000A0BA                 lea     rdx, aPayloadrestric ; "PayloadRestrictions.dll"
.text:000000018000A0C1                 lea     rcx, [rsp+78h+DestinationString] ; DestinationString
.text:000000018000A0C6                 call    cs:__imp_RtlInitUnicodeString
.text:000000018000A0CC                 lea     r9, MitLibHandle
.text:000000018000A0D3                 xor     edx, edx
.text:000000018000A0D5                 lea     r8, [rsp+78h+DestinationString]
.text:000000018000A0DA                 mov     ecx, 4081h
.text:000000018000A0DF                 call    cs:__imp_LdrLoadDll
```
From ntdll.dll we can see that if the mitigations are enabled on a certain process, it will initialize verifier.dll. It's up to verifier.dll to process the mitigation options.

The structure **ntdll!LdrSystemDllInitBlock** is initialized among other values also with **MitigationOptions** and **MitigationAuditOptions**.

The relevant code from the stack trace:
```
00 ffffdf83`6c2c2890 fffff801`d96f186c nt!PspPrepareSystemDllInitBlock+0x11f
01 ffffdf83`6c2c2910 fffff801`d96f5423 nt!PspSetupUserProcessAddressSpace+0x164
02 ffffdf83`6c2c29c0 fffff801`d96cc31f nt!PspAllocateProcess+0xf5f
```

and the disassembled code which stores **MitigationOptions** and **MitigationAuditOptions** into **ntdll!LdrSystemDllInitBlock**:

```
PAGE:00000001404DDA56                                         ; PspPrepareSystemDllInitBlock+10Bj
PAGE:00000001404DDA56                 movups  xmm0, [rsp+78h+var_50]
PAGE:00000001404DDA5B                 movdqu  xmmword ptr [rdi+0A0h], xmm0
PAGE:00000001404DDA63                 movups  xmm1, xmmword ptr [rsp+78h+var_40]
PAGE:00000001404DDA68                 movdqu  xmmword ptr [rdi+0D0h], xmm1
```

The flow from now on is straightforward:

**LdrInitializeProcess** calls **LdrpInitializeExecutionOptions** which in turn checks 2 things: whether verifier is enabled or whether the mitigations are enabled:

```
.text:00000001800D1CFB                 test    dword ptr [r14+0BCh], 2000100h   <-- PEB.NtGlobalFlag check for FLG_HEAP_PAGE_ALLOCS | FLAG_APPLICATION_HEAP_PAGE
.text:00000001800D1D06                 jnz     loc_1800D1DA2
.text:00000001800D1D0C                 call    LdrpPayloadRestrictionMitigationsEnabled
.text:00000001800D1D11                 test    al, al
.text:00000001800D1D13                 jnz     loc_1800D1DA2
...
.text:00000001800D1DA2                 mov     rax, [rbp+1250h+var_1258]
.text:00000001800D1DA6                 movzx   r8d, r12b
.text:00000001800D1DAA                 mov     r9, [rbp+1250h+var_12B8]
.text:00000001800D1DAE                 mov     rdx, r14
.text:00000001800D1DB1                 mov     [rsp+1350h+var_1328], rax
.text:00000001800D1DB6                 mov     rcx, r13
.text:00000001800D1DB9                 mov     rax, [rbp+1250h+var_1250]
.text:00000001800D1DBD                 mov     [rsp+1350h+var_1330], rax
.text:00000001800D1DC2                 call    LdrpInitializeApplicationVerifierPackage
```

If verifier is enabled, it will initialize **verifier.dll**, and if the mitigations are enabled, it will also cause **verifier.dll** to be initialized by calling **LdrpInitializeApplicationVerifierPackage**. Then **verifier.dll** will load **PayloadRestrictions.dll** and this is how the system loads EMET.
