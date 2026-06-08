using System;
using System.Collections.Generic;

namespace Rubeus.Commands
{
    public class Samrchangepw : ICommand
    {
        public static string CommandName => "samrchangepw";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("[*] Action: Change Password via MS-SAMR (NT hash)\r\n");

            string dc = "";
            string user = "";
            string domain = "";
            string oldHash = "";
            string newHash = "";
            bool sspi = false;

            if (arguments.ContainsKey("/dc"))
                dc = arguments["/dc"];

            if (arguments.ContainsKey("/user"))
                user = arguments["/user"];

            if (arguments.ContainsKey("/domain"))
                domain = arguments["/domain"];

            if (arguments.ContainsKey("/old"))
                oldHash = arguments["/old"];

            if (arguments.ContainsKey("/new"))
                newHash = arguments["/new"];

            if (arguments.ContainsKey("/sspi"))
                sspi = true;

            if (String.IsNullOrEmpty(dc))
            {
                Console.WriteLine("[X] /dc is required");
                return;
            }
            if (String.IsNullOrEmpty(user))
            {
                Console.WriteLine("[X] /user is required");
                return;
            }
            if (String.IsNullOrEmpty(domain))
            {
                Console.WriteLine("[X] /domain is required");
                return;
            }
            if (String.IsNullOrEmpty(oldHash))
            {
                Console.WriteLine("[X] /old:<nthash> is required (current NT hash)");
                return;
            }
            if (String.IsNullOrEmpty(newHash))
            {
                Console.WriteLine("[X] /new:<nthash> is required (target NT hash)");
                return;
            }

            byte[] oldNtHash = Helpers.StringToByteArray(oldHash);
            byte[] newNtHash = Helpers.StringToByteArray(newHash);

            if (sspi)
            {
                Smb.SamrPasswordChange.ChangeNtHashLocal(dc, domain, user, oldNtHash, newNtHash);
            }
            else
            {
                Smb.SamrPasswordChange.ChangeNtHash(dc, domain, user, oldNtHash, newNtHash);
            }
        }
    }
}
