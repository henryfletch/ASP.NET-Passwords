using System;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNet.Identity;
using System.Web.Security;
using System.Configuration;
using System.Text;

//ASP.NET Core Identity - Version 3 Password Hashing (SHA256, 10000 iterations)
namespace Microsoft.AspNetCore.Identity
{
    class HasherClassv3 : HasherBase
    {

        public string PasswordHash(string plaintext)
        {
            IPasswordHasher<HasherClassv3> passwordHasher = new PasswordHasher<HasherClassv3>();
            return passwordHasher.HashPassword(null, plaintext);
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

//ASP.NET Identity - Version 2 Password Hashing (SHA1, 1000 iterations)
namespace Microsoft.AspNet.Identity
{
    class HasherClassv2 : HasherBase
    {
        public string PasswordHash(string plaintext)
        {
            IPasswordHasher passwordHasher = new PasswordHasher();
            return passwordHasher.HashPassword(plaintext);
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
//Common class for both Identity Password Hashes
public class HasherBase
{
    public string ConvertToHex(string hash)
    {
        byte[] bytes = Convert.FromBase64String(hash);
        string hex = BitConverter.ToString(bytes);
        return hex;
    }
}

// ASP.NET Forms-based encryption of passwords
public class PasswordEncrypt : SqlMembershipProvider
{
    public string GetClearTextPassword(string encryptedPwd)
    {
        byte[] encodedPassword = Convert.FromBase64String(encryptedPwd);
        byte[] bytes = DecryptPassword(encodedPassword);
        if (bytes == null)
        {
            return null;
        }
        return Encoding.Unicode.GetString(bytes);//, 0x10, bytes.Length - 0x10); //This bit removes the salt if it were present

    }

    public string SetPassword(string cleartext)
    {
        byte[] bytes = Encoding.Unicode.GetBytes(cleartext);
        byte[] bytesOutput = EncryptPassword(bytes);
        string encoded = Convert.ToBase64String(bytesOutput);
        return encoded;
    }
}


class Program
{
    static void Main()
    {
        PasswordEncrypt PasswordEncryptObject = new PasswordEncrypt();
        Program program = new Program(); //This is a bit dodgy?

        Console.WriteLine("Enter password to be encrypted:");
        string plaintext = Console.ReadLine();

        string encoded = PasswordEncryptObject.SetPassword(plaintext);
        Console.WriteLine($"Encrypted output is:{encoded}");
        program.ConsoleContinue();
        Console.ReadKey();

        string plaintext2 = PasswordEncryptObject.GetClearTextPassword(encoded);
        Console.WriteLine($"Decrypted. Plaintext is:{plaintext2}");
        program.ConsoleContinue();
        Console.ReadKey();

        Console.WriteLine("Select hash type. '2' for version 2 or '3' for version 3");
        UInt32 option = program.GetOption();
        string hash = program.Hash(plaintext2, option);

        Console.WriteLine($"Hashed output is: {hash}");
        Console.WriteLine("Press any key to exit");
        Console.ReadKey();
    }

    private string Hash(string plaintext, UInt32 option) //Option defines hasher version 2 or 3
    {
        if (option == 2)
        {
            HasherClassv2 HasherClassObject = new HasherClassv2();
            string hash = HasherClassObject.PasswordHash(plaintext);
            return hash;
        }
        else if (option == 3)
        {
            HasherClassv3 HasherClassObject = new HasherClassv3();
            string hash = HasherClassObject.PasswordHash(plaintext);
            return hash;
        }
        else
        {
            Console.WriteLine("Invalid option selected.");
            return null;
        }

    }

    private void ConsoleContinue()
    {
        Console.WriteLine("Press any key to continue");
    }

    private UInt32 GetOption()
    {
        string input = Console.ReadLine();
        try
        {
            UInt32 option = Convert.ToUInt32(input);
            return option;
        }
        catch
        {
            Console.WriteLine("Invalid option selected. Defaulting to v3.");
            return 3;
        }
    }
}
