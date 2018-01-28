using System;

namespace Microsoft.AspNetCore.Identity
{
    class HasherClassv3
    {

        public string PasswordHash(string plaintext)
        {
            IPasswordHasher<HasherClassv3> passwordHasher = new PasswordHasher<HasherClassv3>();
            return passwordHasher.HashPassword(null, plaintext);
        }

        public string ConvertToHex(string hash)
        {
            byte[] bytes = Convert.FromBase64String(hash);
            string hex = BitConverter.ToString(bytes);
            return hex;
        }

        public string ConvertToHashcat(string hash)
        {
            byte[] bytes = Convert.FromBase64String(hash);

            byte[] prfBytes = new byte[32 / 8];
            byte[] iterBytes = new byte[32 / 8];
            byte[] saltLenBytes = new byte[32 / 8];
            byte[] saltBytes = new byte[128 / 8];
            byte[] subkeyBytes = new byte[256 / 8];

            Buffer.BlockCopy(bytes, 1, prfBytes, 0, 4);
            Buffer.BlockCopy(bytes, 5, iterBytes, 0, 4);
            Buffer.BlockCopy(bytes, 9, saltLenBytes, 0, 4);
            Buffer.BlockCopy(bytes, 13, saltBytes, 0, 16);
            Buffer.BlockCopy(bytes, 29, subkeyBytes, 0, 32);

            Array.Reverse(prfBytes);
            Array.Reverse(iterBytes);
            Array.Reverse(saltLenBytes);

            int prf = BitConverter.ToInt32(prfBytes, 0);
            int iter = BitConverter.ToInt32(iterBytes, 0);
            int saltLen = BitConverter.ToInt32(saltLenBytes, 0);
            string salt = Convert.ToBase64String(saltBytes);
            string subkey = Convert.ToBase64String(subkeyBytes);

            return $"sha256:{iter}:{salt}:{subkey}";

        }
    }
}

namespace Microsoft.AspNet.Identity
{
    class HasherClassv2
    {
        public string PasswordHash(string plaintext)
        {
            IPasswordHasher passwordHasher = new PasswordHasher();
            return passwordHasher.HashPassword(plaintext);
        }

        public string ConvertToHex(string hash)
        {
            byte[] bytes = Convert.FromBase64String(hash);
            string hex = BitConverter.ToString(bytes);
            return hex;
        }

        public string ConvertToHashcat(string hash)
        {
            byte[] bytes = Convert.FromBase64String(hash);

            byte[] saltBytes = new byte[128 / 8];
            byte[] subkeyBytes = new byte[256 / 8];

            Buffer.BlockCopy(bytes, 1, saltBytes, 0, 16);
            Buffer.BlockCopy(bytes, 17, subkeyBytes, 0, 32);

            string salt = Convert.ToBase64String(saltBytes);
            string subkey = Convert.ToBase64String(subkeyBytes);

            return $"sha1:1000:{salt}:{subkey}";

        }

    }
}

class Program
{
    static void Main()
    {
        Microsoft.AspNetCore.Identity.HasherClassv3 HasherClassObject = new Microsoft.AspNetCore.Identity.HasherClassv3();

        Console.WriteLine("Please provide the password to be hashed:");
        string plaintext = Console.ReadLine();

        string hash = HasherClassObject.PasswordHash(plaintext);
        string hex = HasherClassObject.ConvertToHex(hash);
        string hashcat = HasherClassObject.ConvertToHashcat(hash);

        Console.WriteLine($"The result is: {hash}");
        Console.WriteLine($"The hex is: {hex}");
        Console.WriteLine($"Hashcat: {hashcat}");
        Console.WriteLine("Press any key to exit");
        Console.ReadKey();
    }
}