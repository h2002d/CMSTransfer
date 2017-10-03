using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices.AccountManagement;
using System.Collections;
using System.Security.Cryptography;
using System.IO;
using System.Net.Http;
using System.Configuration;
using System.IO.Compression;
using System.Diagnostics;
using System.ServiceProcess;

namespace Update
{
    class Program
    {
        static string webAddress = ConfigurationManager.AppSettings["webhost"];
   
        
        static string appDirectory = AppDomain.CurrentDomain.BaseDirectory;
        //async method to download the file

        static async void GetUpdateFile()
        {

            try
            {
                //instance of HTTPClient
                HttpClient client = new HttpClient();

                HttpResponseMessage responseDownload = await client.GetAsync(webAddress + "\\download.php");
              
                // Check that response was successful or throw exception
                responseDownload.EnsureSuccessStatusCode();
                // Read response asynchronously and save asynchronously to file

                using (FileStream fileStream = new FileStream(appDirectory+"\\update.zip", FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    //copy the content from response to filestream
                    await responseDownload.Content.CopyToAsync(fileStream);
                    //UnZipCatalog(fileStream);
                }
                using (ZipArchive archive = ZipFile.OpenRead(appDirectory + "\\update.zip"))
                {
                    foreach (ZipArchiveEntry entry in archive.Entries)
                    {
                        //if (entry.FullName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)||)
                        //{
                            entry.ExtractToFile(Path.Combine(appDirectory, entry.FullName), true);
                        //}
                    }
                }
              
                using (ServiceController sc = new ServiceController("CMS Monitor Service"))
                {
                    sc.Start();
                }
            }
            catch (HttpRequestException rex)
            {
                Console.WriteLine(rex.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }


       
        static void Main(string[] args)
        {
            GetUpdateFile();

            Console.WriteLine("Hit  enter to exit...");
            Console.ReadLine();
        }

    }
}
