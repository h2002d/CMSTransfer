using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices.AccountManagement;
using System.Collections;

namespace ConsoleApp1
{
    class Program
    {

        static void Main(string[] args)
        {
            string date = "20170923212205.611873+24";
            Console.WriteLine(date.Substring(6, 2) + "/" + date.Substring(4, 2) + "/" + date.Substring(0, 4));
            Console.ReadKey();
        }
        public string GetConvertedDate(string date)
        {
            return date.Substring(6, 2) + "/" + date.Substring(4, 2) + "/" + date.Substring(0, 4);
        }
    }
}
