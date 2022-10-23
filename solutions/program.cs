using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;


namespace Sain
{
    internal static class Locker {
        private static readonly string EncryptedFileListPath = "EncryptedFileList.txt";
        private static readonly HashSet<string> EncryptedFiles = new HashSet<string>();
        private const string EncryptionFileExtension = ".fun";
        private const string EncryptionPassword = "OoIsAwwF32cICQoLDA0ODe==";

        internal static HashSet<string> GetEncryptedFiles()
        {
            HashSet<string> encryptedFiles = new HashSet<string>();
            if (File.Exists(Locker.EncryptedFileListPath))
            {
                foreach (string readAllLine in File.ReadAllLines(Locker.EncryptedFileListPath))
                    encryptedFiles.Add(readAllLine);
            }
            return encryptedFiles;
        }

        private static string CreateFileSystemSimulation()
        {
            string path1 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "..\\");
            using (TextWriter textWriter = (TextWriter)new StreamWriter(Path.Combine(path1, "TxtTest.txt"), true))
                textWriter.WriteLine("I am a txt test.");
            return path1;
        }

        private static IEnumerable<string> GetExtensionsToEncrypt()
        {
            HashSet<string> extensionsToEncrypt1 = new HashSet<string>();
            string extensionsToEncrypt2 = ".fun";
            string[] separator = new string[2]
            {
        Environment.NewLine,
        " "
            };
            foreach (string str in ((IEnumerable<string>)extensionsToEncrypt2.Split(separator, StringSplitOptions.RemoveEmptyEntries)).ToList<string>())
                extensionsToEncrypt1.Add(str.Trim());
            extensionsToEncrypt1.Remove(".fun");
            return (IEnumerable<string>)extensionsToEncrypt1;
        }

        private static IEnumerable<string> GetFiles(string path)
        {
            Queue<string> queue = new Queue<string>();
            queue.Enqueue(path);
            while (queue.Count > 0)
            {
                path = queue.Dequeue();
                try
                {
                    string[] strArray = Directory.GetDirectories(path);
                    for (int index = 0; index < strArray.Length; ++index)
                    {
                        string subDir = strArray[index];
                        queue.Enqueue(subDir);
                        subDir = (string)null;
                    }
                    strArray = (string[])null;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine((object)ex);
                }
                string[] files = (string[])null;
                try
                {
                    files = Directory.GetFiles(path);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine((object)ex);
                }
                if (files != null)
                {
                    string[] strArray = files;
                    for (int index = 0; index < strArray.Length; ++index)
                    {
                        string t = strArray[index];
                        yield return t;
                        t = (string)null;
                    }
                    strArray = (string[])null;
                    files = (string[])null;
                }
            }
        }

        internal static void DecryptFiles(string encryptionExtension)
        {
            foreach (string encryptedFile in Locker.GetEncryptedFiles())
            {
                try
                {
                    string path = encryptedFile + encryptionExtension;
                    Locker.DecryptFile(path, encryptionExtension);
                    File.Delete(path);
                }
                catch
                {
                }
            }
            File.Delete(Locker.EncryptedFileListPath);

            try
            {
                string path = "file" + encryptionExtension;
                Locker.DecryptFile(path, encryptionExtension);
                File.Delete(path);
            }
            catch
            {
            }
        }

        private static void DecryptFile(string path, string encryptionExtension)
        {
            try
            {
                if (!path.EndsWith(encryptionExtension))
                    return;
                string outputFile = path.Remove(path.Length - 4);
                using (AesCryptoServiceProvider alg = new AesCryptoServiceProvider())
                {
                    alg.Key = Convert.FromBase64String("OoIsAwwF32cICQoLDA0ODe==");
                    alg.IV = new byte[16]
                    {
            (byte) 0,
            (byte) 1,
            (byte) 0,
            (byte) 3,
            (byte) 5,
            (byte) 3,
            (byte) 0,
            (byte) 1,
            (byte) 0,
            (byte) 0,
            (byte) 2,
            (byte) 0,
            (byte) 6,
            (byte) 7,
            (byte) 6,
            (byte) 0
                    };
                    Locker.DecryptFile((SymmetricAlgorithm)alg, path, outputFile);
                }
            }
            catch
            {
                return;
            }
            try
            {
                File.Delete(path);
            }
            catch (Exception ex)
            {
            }
        }

        private static void DecryptFile(SymmetricAlgorithm alg, string inputFile, string outputFile)
        {
            byte[] buffer = new byte[65536];
            using (FileStream fileStream1 = new FileStream(inputFile, FileMode.Open))
            {
                using (FileStream fileStream2 = new FileStream(outputFile, FileMode.Create))
                {
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)fileStream2, alg.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        int count;
                        do
                        {
                            count = fileStream1.Read(buffer, 0, buffer.Length);
                            if (count != 0)
                                cryptoStream.Write(buffer, 0, count);
                        }
                        while (count != 0);
                    }
                }
            }
        }
    }
}

namespace Application
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello, World!");
            Sain.Locker.DecryptFiles(".fun");
        }
    }
}