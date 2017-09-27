using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices;
using System.Management;
using Newtonsoft.Json;
using System.Net.Http;
using System.Security.Principal;
using Newtonsoft.Json.Linq;
using System.DirectoryServices.AccountManagement;
using System.Collections;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Security.Cryptography;

namespace VendorCMS
{
    public partial class Service1 : ServiceBase
    {
        static bool is64BitProcess = (IntPtr.Size == 8);
        static bool is64BitOperatingSystem = is64BitProcess || InternalCheckIsWow64();

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsWow64Process(
            [In] IntPtr hProcess,
            [Out] out bool wow64Process
        );

        string logsDirectory = AppDomain.CurrentDomain.BaseDirectory;
        public StringBuilder webData = new StringBuilder(string.Format("{{\"SID\":\"{0}\",", GetComputerSid().Value));
        public Service1()
        {
            InitializeComponent();
            this.CanStop = false;

        }
        public static string EncryptMessage(byte[] text, string key)
        {
            RijndaelManaged aes = new RijndaelManaged();
            aes.KeySize = 256;
            aes.BlockSize = 256;
            aes.Padding = PaddingMode.Zeros;
            aes.Mode = CipherMode.CBC;

            aes.Key = Encoding.Default.GetBytes("770A8A65DA156D24EE2A093277530142");
            aes.GenerateIV();

            string IV = ("-[--IV-[-" + Encoding.Default.GetString(aes.IV));

            ICryptoTransform AESEncrypt = aes.CreateEncryptor(aes.Key, aes.IV);
            byte[] buffer = text;

            return
        Convert.ToBase64String(Encoding.Default.GetBytes(Encoding.Default.GetString(AESEncrypt.TransformFinalBlock(buffer, 0, buffer.Length)) + IV));

        }
        protected override void OnStart(string[] args)
        {

            try
            {
                Task t = new Task(() => TimerTaskAsync());
                t.Start();
            }
            catch (Exception ex)
            {
                SaveFile("GlobalError.txt", ex.Message + "   " + ex.StackTrace);
            }
        }
        public async void TimerTaskAsync()
        {
           
            while (true)
            {

                while (DayPassed())
                {

                    ExportData();
                    Task t = new Task(() => CallWebServiceAsync());
                    t.Start();

                    t.Wait();
                    await Task.Delay(TimeSpan.FromHours(24));

                }
            }
        }
        public string CallBackStatus()
        {
            string text;
            try
            {
                text = System.IO.File.ReadAllText(logsDirectory + "\\webServiceCallback.txt");
            }
            catch
            {
                text = "";
            }
            // Display the file contents to the console. Variable text is a string.
            return text;

        }
        protected override void OnStop()
        {
        }

        private void ExportData()
        {
            ExportShares();
            ExportProcesses();//Exports file related to Process info.CMS_PROCESS Done!
            ExportMachineName();//Exports PC information.
            ExportSoftwareInstalled();//Exports all installed softs info.CMS_APPLICATIONS
            ExportIpInformation();//Exports Mac Address and ip addresses. CMS_IP
            ExportLocalGroups();//Exports LocalGroups information. CMS_LocalGroups
            ExportLocalUsers();//Exports Local User information.CMS_LOCALUSERS
            ExportOSInformation();
            ExportServices();
            ExportHardware();
            ExportLogon();

        }

        private void ExportShares()
        {
            StringBuilder userData = new StringBuilder("");
            try
            {

                ManagementObjectSearcher searcher = new ManagementObjectSearcher("Select * from Win32_Share Where Type=\"0\"");
                userData.Append(@" ""shares"":[");

                var shares = searcher.Get();

                foreach (ManagementObject envVar in shares)
                {
                    userData.Append(string.Format("{{\"Name\":\"{0}\",", envVar["Name"]))
                   .Append(string.Format("\"Path\":\"{0}\"}},", envVar["Path"]));
                }

                
              
                if (shares.Count == 0)
                {
                    userData.Append("],");
                }
                else
                {
                    userData.Remove(userData.Length - 1, 1);
                    userData.Append("],");
                }
                webData.Append(userData.ToString());
            }
            catch (Exception ex)
            {

                SaveFile("sharesError.txt", ex.Message + "    " + ex.InnerException + ex.StackTrace);
            }
            finally
            {
                SaveFile("shares.txt", userData.ToString());
            }
        }

        private void ExportLogon()
        {

            StringBuilder userData = new StringBuilder("");
            try
            {

                userData.Append(@" ""logon"":[");

                //RegistryKey OurKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList", true);
                //dynamic profiles;
                //TryGetRegistryKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
                //    "PROFILESDIRECTORY", out profiles);

                //String dir=profiles.Substring(profiles.Length - 2) + @"\".Replace(@"\", @"\").Replace(@"\\\", @"\\");
                //String drive = profiles.Substring(0, 2);
                //userData.Append("dir:"+dir);
                //userData.Append("profiles:" + profiles);

                ObjectQuery accountQuery = new ObjectQuery(@"Select * FROM Win32_ComputerSystem");
                //Win32_Directory
                //ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_Directory Where Name=\"c:\\\\\"");
                //WHERE Hidden = false And Path = '"+dir+"' And drive = '"+drive+"'
                ManagementObjectSearcher searcherAccount = new ManagementObjectSearcher(accountQuery);

                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Directory Where Path=\"\\\\Users\\\\\"");
                foreach (ManagementObject envVar in searcher.Get())
                {
                    userData.Append(string.Format("{{\"FileName\":\"{0}MB\",", envVar["FileName"]))
                   .Append(string.Format("\"Name\":\"{0}\",", envVar["Name"].ToString().Replace(@"\", @"\\")))
                   .Append(string.Format("\"LastModified\":\"{0}\",", GetConvertedDate(envVar["LastModified"].ToString())))
                   .Append(string.Format("\"LastAccessed\":\"{0}\",", GetConvertedDate(envVar["LastAccessed"].ToString())))


                   .Append(string.Format("\"CreationDate\":\"{0}\"}},", GetConvertedDate(envVar["CreationDate"].ToString())));


                }


                userData.Remove(userData.Length - 1, 1);
                userData.Append("],");

                webData.Append(userData.ToString());
            }
            catch (Exception ex)
            {
                SaveFile("LogonErmmmmmmror.txt", ex.Message + "    " + ex.InnerException + ex.StackTrace);
            }
            finally
            {
                SaveFile("LogonUsemmmmmr.txt", userData.ToString());
            }
        }

        public string GetConvertedDate(string date)
        {
            return date.Substring(6, 2) + "/" + date.Substring(4, 2) + "/" + date.Substring(0, 4);
        }
        private void ExportHardware()
        {
            StringBuilder userData = new StringBuilder("");
            try
            {

                userData.Append(@" ""hardware"":[");


                SelectQuery accountQuery = new SelectQuery("Win32_ComputerSystem");
                ManagementObjectSearcher searcherAccount = new ManagementObjectSearcher(accountQuery);

                foreach (ManagementObject envVar in searcherAccount.Get())
                {
                    userData.Append(string.Format("{{\"TotalMemory\":\"{0}MB\",", Convert.ToInt64(envVar["TotalPhysicalMemory"]) / 1024.0))
                   .Append(string.Format("\"Model\":\"{0}\",", envVar["Model"]))
                   .Append(string.Format("\"NumberOfProcessors\":\"{0}\",", envVar["NumberOfProcessors"]))                   
                   .Append(string.Format("\"Manufacturer\":\"{0}\",", envVar["Manufacturer"]));
                }
                SelectQuery biosQuery = new SelectQuery("Win32_BIOS");
                ManagementObjectSearcher biosInfo = new ManagementObjectSearcher(biosQuery);

                foreach (ManagementObject envVar in biosInfo.Get())
                {
                    userData.Append(string.Format("\"BIOSVersion\":\"{0}\",", envVar["Version"]));
                    userData.Append(string.Format("\"BIOSCaption\":\"{0}\",", envVar["Caption"]));
                    userData.Append(string.Format("\"BIOSSerialNumber\":\"{0}\",", envVar["SerialNumber"]));
                    userData.Append(string.Format("\"BIOSManufacturer\":\"{0}\",", envVar["Manufacturer"]));
                }

                SelectQuery boardQuery = new SelectQuery("Win32_BaseBoard");
                ManagementObjectSearcher boardInfo = new ManagementObjectSearcher(boardQuery);

                foreach (ManagementObject envVar in boardInfo.Get())
                {
                    userData.Append(string.Format("\"BoardProduct\":\"{0}\",", envVar["Product"]))

                   .Append(string.Format("\"BoardManufacturer\":\"{0}\",", envVar["Manufacturer"]));
                }

                SelectQuery enclosureQuery = new SelectQuery("Win32_SystemEnclosure");
                ManagementObjectSearcher enclosureInfo = new ManagementObjectSearcher(enclosureQuery);

                foreach (ManagementObject envVar in enclosureInfo.Get())
                {
                    userData.Append(string.Format("\"EnclosureSerialNumber\":\"{0}\",", envVar["SerialNumber"]))
                   .Append(string.Format("\"EnclosureModel\":\"{0}\",", envVar["Model"]))
                   .Append(string.Format("\"EnclosureName\":\"{0}\",", envVar["Name"]))
                   .Append(string.Format("\"EnclosureManufacturer\":\"{0}\",", envVar["Manufacturer"]));
                }
                SelectQuery proccesorQuery = new SelectQuery("Win32_Processor");
                ManagementObjectSearcher proccesorInfo = new ManagementObjectSearcher(proccesorQuery);

                foreach (ManagementObject envVar in proccesorInfo.Get())
                {
                    userData.Append(string.Format("\"NumberOfCores\":\"{0}\",", envVar["NumberOfCores"]))
                   .Append(string.Format("\"NumberOfLogicalProcessors\":\"{0}\",", envVar["NumberOfLogicalProcessors"]));
                
                }

           
                
                userData.Remove(userData.Length - 1, 1);
                userData.Append("}");
                userData.Append("],");

                webData.Append(userData.ToString());
            }
            catch (Exception ex)
            {
                SaveFile("LogonError.txt", ex.Message + "    " + ex.InnerException + ex.StackTrace);
            }
            finally
            {
                SaveFile("LogonUser.txt", userData.ToString());
            }
        }

        private void ExportServices()
        {
            ServiceController[] services = ServiceController.GetServices();
            StringBuilder data = new StringBuilder("");
            data.Append(@" ""service"":[");
            foreach (var service in services)
            {
                if (service.DisplayName.Equals(String.Empty))
                {
                    continue;
                }

                data.Append(string.Format("{{\"ServiceDisplayName\":\"{0}\",", Regex.Replace(service.DisplayName.Replace("\"", "\\\""), @"\t|\n|\r", "")))
               .Append(string.Format("\"ServiceName\":\"{0}\",", service.ServiceName))
               .Append(string.Format("\"ServiceStatus\":\"{0}\",", service.Status))
               .Append(string.Format("\"ServiceType\":\"{0}\",", service.ServiceType))
               .Append(string.Format("\"ServicePath\":\"{0}\"}},", GetServiceExecutablePath(service.ServiceName)));
            }
            data.Remove(data.Length - 1, 1);
            data.Append("],");
            webData.Append(data.ToString());
        }

        private string GetServiceExecutablePath(string serviceName)
        {
            ManagementClass mc = new ManagementClass("Win32_Service");
            foreach (ManagementObject mo in mc.GetInstances())
            {
                if (mo.GetPropertyValue("Name").ToString() == serviceName)
                {

                    return mo.GetPropertyValue("PathName").ToString().Trim('"').Replace("\\", "\\\\").Replace("\"", "\\\"");
                }
            }
            return "";
        }

        private void ExportOSInformation()
        {
            StringBuilder data = new StringBuilder("");
            data.Append(@" ""osInfo"":[");

            data.Append(string.Format("{{\"VersionName\":\"{0}\",", FriendlyName()))
            .Append(string.Format("\"VersionNumber\":\"{0}\"}}", WinMajorVersion.ToString()));


            data.Append("],");
            webData.Append(data.ToString());
        }

        public static uint WinMajorVersion
        {
            get
            {
                dynamic major;
                // The 'CurrentMajorVersionNumber' string value in the CurrentVersion key is new for Windows 10, 
                // and will most likely (hopefully) be there for some time before MS decides to change this - again...
                if (TryGetRegistryKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentMajorVersionNumber", out major))
                {
                    return (uint)major;
                }

                // When the 'CurrentMajorVersionNumber' value is not present we fallback to reading the previous key used for this: 'CurrentVersion'
                dynamic version;
                if (!TryGetRegistryKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentVersion", out version))
                    return 0;

                var versionParts = ((string)version).Split('.');
                if (versionParts.Length != 2) return 0;
                uint majorAsUInt;
                return uint.TryParse(versionParts[0], out majorAsUInt) ? majorAsUInt : 0;
            }
        }

        public string HKLM_GetString(string path, string key)
        {
            try
            {
                RegistryKey rk = Registry.LocalMachine.OpenSubKey(path);
                if (rk == null) return "";
                return (string)rk.GetValue(key);
            }
            catch { return ""; }
        }

        public string FriendlyName()
        {
            string ProductName = HKLM_GetString(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName");
            string CSDVersion = HKLM_GetString(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CSDVersion");
            if (ProductName != "")
            {
                return (ProductName.StartsWith("Microsoft") ? "" : "Microsoft ") + ProductName +
                            (CSDVersion != "" ? " " + CSDVersion : "");
            }
            return "";
        }

        private void SaveFile(string fileName, string data)
        {
            //string fileNameFull = Path.Combine(
            //    Environment.GetFolderPath(),
            //    fileName);
            FileInfo fileusername = new FileInfo(logsDirectory + @"\" + fileName);
            StreamWriter namewriter = fileusername.CreateText();
            namewriter.Write(data);
            namewriter.Close();
        }

        private void ExportProcesses()
        {
            Process[] processlist = Process.GetProcesses();
            StringBuilder data = new StringBuilder("");
            data.Append(@" ""process"":[");
            foreach (Process theprocess in processlist)
            {
                data.Append(string.Format("{{\"ProcessName\":\"{0}\",", theprocess.ProcessName))
                .Append(string.Format("\"ProcessId\":\"{0}\"}},", theprocess.Id));

            }
            data.Remove(data.Length - 1, 1);
            data.Append("],");
            webData.Append(data.ToString());
            SaveFile("processes.txt", data.ToString());
        }

        private void ExportMachineName()
        {
            StringBuilder machineData = new StringBuilder("");
            machineData.Append(@" ""machine"":[")
            .Append(string.Format("{{\"PcName\":\"{0}\",", System.Environment.MachineName))
            .Append(string.Format("\"SID\":\"{0}\",", GetComputerSid().Value))
                .Append(string.Format("\"FullPcName\":\"{0}\"}}", System.Net.Dns.GetHostEntry("").HostName))
            .Append("],");
            webData.Append(machineData.ToString());

            SaveFile("machine.txt", machineData.ToString());
        }

        public static SecurityIdentifier GetComputerSid()
        {
            return new SecurityIdentifier((byte[])new DirectoryEntry(string.Format("WinNT://{0},Computer", Environment.MachineName)).Children.Cast<DirectoryEntry>().First().InvokeGet("objectSID"), 0).AccountDomainSid;
        }
        //Softwareinfo is done.
        private void ExportSoftwareInstalled()
        {
            StringBuilder softData = new StringBuilder("");
            StringBuilder exception = new StringBuilder("");
            string registry_key = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
            using (Microsoft.Win32.RegistryKey key = Registry.LocalMachine.OpenSubKey(registry_key))
            {

                try
                {
                    softData.Append(@" ""software"":[");
                    foreach (string subkey_name in key.GetSubKeyNames())
                    {
                        using (RegistryKey subkey = key.OpenSubKey(subkey_name))
                        {
                            if (subkey.GetValue("DisplayName") == null)
                            {
                                continue;
                            }
                            softData.Append(string.Format("{{\"DisplayName\":\"{0}\",", Regex.Replace(subkey.GetValue("DisplayName").ToString().Replace("\"", "\\\""), @"\t|\n|\r", "")));
                            softData.Append(string.Format("\"InstallDate\":\"{0}\",", subkey.GetValue("InstallDate")));
                            softData.Append(string.Format("\"DisplayVersion\":\"{0}\",", subkey.GetValue("DisplayVersion")));
                            softData.Append(string.Format("\"VersionMajor\":\"{0}\",", subkey.GetValue("VersionMajor")));
                            softData.Append(string.Format("\"Publisher\":\"{0}\"}},", subkey.GetValue("Publisher")));
                        }
                    }
                }
                catch (Exception ex)
                {
                    exception.Append(ex.Message + "    " + ex.StackTrace);
                    SaveFile("errorLog.txt", exception.ToString());

                }


            }
            if (is64BitOperatingSystem)
            {
                string registry_keyAdditional = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";
                using (Microsoft.Win32.RegistryKey key = Registry.LocalMachine.OpenSubKey(registry_keyAdditional))
                {

                    try
                    {

                        foreach (string subkey_name in key.GetSubKeyNames())
                        {
                            using (RegistryKey subkey = key.OpenSubKey(subkey_name))
                            {

                                softData.Append(string.Format("{{\"DisplayName\":\"{0}\",", subkey.GetValue("DisplayName")));
                                softData.Append(string.Format("\"InstallDate\":\"{0}\",", subkey.GetValue("InstallDate")));
                                softData.Append(string.Format("\"DisplayVersion\":\"{0}\",", subkey.GetValue("DisplayVersion")));
                                softData.Append(string.Format("\"VersionMajor\":\"{0}\",", subkey.GetValue("VersionMajor")));
                                softData.Append(string.Format("\"Publisher\":\"{0}\"}},", subkey.GetValue("Publisher")));
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        exception.Append(ex.Message);
                        SaveFile("errorLog.txt", exception.ToString());

                    }


                }
            }
            softData.Remove(softData.Length - 1, 1);
            softData.Append("],");
            webData.Append(softData.ToString());
            SaveFile("software.txt", softData.ToString());
        }

        

        public async void CallWebServiceAsync()
        {
            try
            {
                while (!CheckIfPassed())
                {

                    string page = "http://novir.ga/";
                    webData.Remove(webData.Length - 1, 1);
                    webData.Append("}");
                    //Newtonsoft.Json.Linq.JToken token = Newtonsoft.Json.Linq.JToken.Parse(webData.ToString());
                    // JObject json = JsonObjectAttribute.Parse((string)token);         
                    // string quotesEscapedData = EscapeForJson(webData.ToString());
                    JsonStringifier str = new JsonStringifier();

                    str.JsonString = webData.ToString();
                    var sz = JsonConvert.SerializeObject(str);
                    string encrypted= EncryptMessage(Encoding.ASCII.GetBytes(sz), "");
                    var contentParams = new StringContent(encrypted, Encoding.UTF8, "application/json");
                    SaveFile("webServiceCallbackData.txt", encrypted);


                    // ... Use HttpClient.
                    using (HttpClient client = new HttpClient())
                    using (HttpResponseMessage response = await client.PostAsync(page, contentParams))
                    using (HttpContent content = response.Content)
                    {
                        // ... Read the string.
                        string result = await content.ReadAsStringAsync();

                        // ... Display the result.
                        if (result != null)
                        {
                            SaveFile("webServiceCallback.txt", result);
                        }
                        return;
                    }

                }
            }
            catch (Exception ex)
            {
                SaveFile("webServiceCallbackError.txt", ex.Message + "   " + ex.InnerException + "   " + ex.StackTrace);
                return;
            }

        }

        public bool CheckIfPassed()
        {
            return CallBackStatus().Equals("success");
        }

        public bool DayPassed()
        {

            DateTime dt = File.GetLastWriteTime(logsDirectory + "\\webServiceCallback.txt");
            DateTime timeOfLastPaswordReset = dt;

            DateTime now = DateTime.Now;
            TimeSpan diference = now.Subtract(timeOfLastPaswordReset);
            return !(diference < TimeSpan.FromHours(24));
        }

        private void ExportIpInformation()
        {
            StringBuilder data = new StringBuilder("");
            data.Append(@" ""netInfo"":[");
            GetMACAddress(ref data);
            GetIpAdresses(ref data);
            data.Append("],");
            webData.Append(data.ToString());
            SaveFile("ipMacAddress.txt", data.ToString());

        }

        public void GetIpAdresses(ref StringBuilder data)
        {
            String strHostName = string.Empty;
            // Getting Ip address of local machine...
            // First get the host name of local machine.
            strHostName = Dns.GetHostName();

            // Then using host name, get the IP address list..
            IPHostEntry ipEntry = Dns.GetHostEntry(strHostName);
            IPAddress[] addr = ipEntry.AddressList;
            data.Append(string.Format("\"IpAddress\":\""));
            foreach (var address in addr)
            {
                data.Append(string.Format("{0};", address.ToString()));
            }
            data.Append(string.Format("\"}}"));

        }

        public void GetMACAddress(ref StringBuilder data)
        {
            NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
            String sMacAddress = string.Empty;
            foreach (NetworkInterface adapter in nics)
            {
                if (sMacAddress == String.Empty)// only return MAC Address from first card  
                {
                    //IPInterfaceProperties properties = adapter.GetIPProperties(); Line is not required
                    sMacAddress = adapter.GetPhysicalAddress().ToString();
                    data.Append(string.Format("{{\"MacAddress\":\"{0}\",", sMacAddress));


                }
            }
        }

        private void ExportLocalGroups()
        {
            StringBuilder data = new StringBuilder("");
            data.Append(@" ""localgroups"":[");
            GetGruops(ref data);
            data.Remove(data.Length - 1, 1);
            data.Append("],");
            webData.Append(data.ToString());
            SaveFile("LocalGroups.txt", data.ToString());
        }

        public void GetGruops(ref StringBuilder data)
        {
            DirectoryEntry machine = new DirectoryEntry("WinNT://" + Environment.MachineName + ",Computer");
            foreach (DirectoryEntry child in machine.Children)
            {
                if (child.SchemaClassName == "Group")
                {
                    data.Append(string.Format("{{\"GroupName\":\"{0}\",", child.Name))
                    .Append(string.Format("\"GroupProperty\":\"{0}\"}},", child.Properties));
                }
            }
        }

        private void ExportLocalUsers()
        {
            try
            {
                StringBuilder userData = new StringBuilder("");
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("Select * from Win32_UserAccount Where LocalAccount = True");
                userData.Append(@" ""user"":[");


                foreach (ManagementObject envVar in searcher.Get())
                {
                    userData.Append(string.Format("{{\"UserName\":\"{0}\",", envVar["Name"]))
                   .Append(string.Format("\"AccountType\":\"{0}\",", envVar["AccountType"]))
                   .Append(string.Format("\"Description\":\"{0}\",", envVar["Description"]))
                   .Append(string.Format("\"Disabled\":\"{0}\",", envVar["Disabled"]))
                   .Append(string.Format("\"Domain\":\"{0}\",", envVar["Domain"]))
                   .Append(string.Format("\"Lockout\":\"{0}\",", envVar["Lockout"]))
                   .Append(string.Format("\"PasswordChangeable\":\"{0}\",", envVar["PasswordChangeable"]))
                   .Append(string.Format("\"PasswordExpires\":\"{0}\",", envVar["PasswordExpires"]))
                   .Append(string.Format("\"PasswordRequired\":\"{0}\",", envVar["PasswordRequired"]))
                   .Append(string.Format("\"Status\":\"{0}\",", envVar["Status"]))
                   .Append(string.Format("\"LocalAccount\":\"{0}\",", envVar["LocalAccount"]))
                   .Append(string.Format("\"LocalUserGroups\":\""));
                    foreach (var item in GetUserGroups(envVar["Name"].ToString()))
                    {
                        userData.Append(item.ToString() + " , ");

                    }

                    userData.Append(string.Format("\",\"InstallDate\":\"{0}\"}},", envVar["InstallDate"]));


                }
                userData.Remove(userData.Length - 1, 1);
                userData.Append("],");
                webData.Append(userData.ToString());
                SaveFile("LocalUsers.txt", userData.ToString());
            }
            catch (Exception ex)
            {
                SaveFile("LocalUsers.txt", ex.Message.ToString());
            }
        }


        private static bool TryGetRegistryKey(string path, string key, out dynamic value)
        {
            value = null;
            try
            {
                using (var rk = Registry.LocalMachine.OpenSubKey(path))
                {
                    if (rk == null) return false;
                    value = rk.GetValue(key);
                    return value != null;
                }
            }
            catch
            {
                return false;
            }
        }

        public static ArrayList GetUserGroups(string sUserName)
        {
            ArrayList myItems = new ArrayList();
            UserPrincipal oUserPrincipal = GetUser(sUserName);

            PrincipalSearchResult<Principal> oPrincipalSearchResult = oUserPrincipal.GetGroups();

            foreach (Principal oResult in oPrincipalSearchResult)
            {
                myItems.Add(oResult.Name);
            }
            return myItems;
        }

        public static UserPrincipal GetUser(string sUserName)
        {
            PrincipalContext oPrincipalContext = GetPrincipalContext();

            UserPrincipal oUserPrincipal = UserPrincipal.FindByIdentity(oPrincipalContext, sUserName);
            return oUserPrincipal;
        }

        public static PrincipalContext GetPrincipalContext()
        {
            PrincipalContext oPrincipalContext = new PrincipalContext(ContextType.Machine);
            return oPrincipalContext;
        }


        public static bool InternalCheckIsWow64()
        {
            if ((Environment.OSVersion.Version.Major == 5 && Environment.OSVersion.Version.Minor >= 1) ||
                Environment.OSVersion.Version.Major >= 6)
            {
                using (Process p = Process.GetCurrentProcess())
                {
                    bool retVal;
                    if (!IsWow64Process(p.Handle, out retVal))
                    {
                        return false;
                    }
                    return retVal;
                }
            }
            else
            {
                return false;
            }
        }
    }
}
