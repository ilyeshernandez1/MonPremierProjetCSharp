using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;

class PasswordStorage
{
  private const string PasswordsFileName = "encrypted_passwords.txt";
  private const string MasterPasswordFileName = "master_password.txt";

  public static void SavePassword(string passwordName, string password, SecureString encryptionKey)
  {
    try
    {
      Dictionary<string, string> existingPasswords = LoadPasswords(encryptionKey);

      // Ajouter ou mettre à jour le mot de passe
      existingPasswords[passwordName] = password;

      // Sauvegarder le dictionnaire mis à jour
      SavePasswords(existingPasswords, encryptionKey);

      Console.WriteLine("Password saved successfully.");
    }
    catch (Exception ex)
    {
      Console.WriteLine($"Error saving password: {ex.Message}");
    }
  }

  public static Dictionary<string, string> LoadPasswords(SecureString encryptionKey)
  {
    try
    {
      if (File.Exists(PasswordsFileName))
      {
        byte[] encryptedPasswords = File.ReadAllBytes(PasswordsFileName);
        string decryptedPasswordsString = DecryptStringFromBytes_Aes(encryptedPasswords, encryptionKey.ToString());

        // Vérifier si le contenu est correctement déchiffré
        if (string.IsNullOrEmpty(decryptedPasswordsString))
        {
          Console.WriteLine("Error: Unable to decrypt passwords. Incorrect encryption key or corrupted file.");
          return new Dictionary<string, string>();
        }

        // Charger le dictionnaire depuis la chaîne déchiffrée
        return StringToDictionary(decryptedPasswordsString);
      }
      else
      {
        Console.WriteLine($"No passwords found in '{PasswordsFileName}'.");
        return new Dictionary<string, string>();
      }
    }
    catch (Exception ex)
    {
      Console.WriteLine($"Error loading passwords: {ex.Message}");
      return new Dictionary<string, string>();
    }
  }

  private static Dictionary<string, string> StringToDictionary(string input)
  {
    Dictionary<string, string> dictionary = new Dictionary<string, string>();

    if (!string.IsNullOrEmpty(input))
    {
      string[] pairs = input.Split(';');
      foreach (string pair in pairs)
      {
        string[] keyValue = pair.Split(':');
        if (keyValue.Length == 2)
        {
          string key = keyValue[0];
          string value = keyValue[1];
          dictionary[key] = value;
        }
      }
    }

    return dictionary;
  }

  private static string DictionaryToString(Dictionary<string, string> dictionary)
  {
    StringBuilder result = new StringBuilder();

    foreach (var entry in dictionary)
    {
      result.Append($"{entry.Key}:{entry.Value};");
    }

    return result.ToString().TrimEnd(';');
  }

  private static void SavePasswords(Dictionary<string, string> passwords, SecureString encryptionKey)
  {
    try
    {
      // Convert the dictionary to a string
      string passwordsString = DictionaryToString(passwords);

      // Encrypt and save the string
      byte[] encryptedPasswords = EncryptStringToBytes_Aes(passwordsString, encryptionKey.ToString());
      File.WriteAllBytes(PasswordsFileName, encryptedPasswords);

      Console.WriteLine("Passwords saved successfully.");
    }
    catch (Exception ex)
    {
      Console.WriteLine($"Error saving passwords: {ex.Message}");
    }
  }


  private static byte[] EncryptStringToBytes_Aes(string plainText, string key)
  {
    using (Aes aesAlg = Aes.Create())
    {
      // Assurez-vous que la clé a une longueur valide
      aesAlg.Key = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32));
      aesAlg.IV = new byte[aesAlg.BlockSize / 8];

      ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

      using (MemoryStream msEncrypt = new MemoryStream())
      {
        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
        {
          using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
          {
            swEncrypt.Write(plainText);
          }
        }
        return msEncrypt.ToArray();
      }
    }
  }

  private static string DecryptStringFromBytes_Aes(byte[] cipherText, string key)
  {
    using (Aes aesAlg = Aes.Create())
    {
      // Assurez-vous que la clé a une longueur valide
      aesAlg.Key = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32));
      aesAlg.IV = new byte[aesAlg.BlockSize / 8];

      ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

      using (MemoryStream msDecrypt = new MemoryStream(cipherText))
      {
        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
        {
          using (StreamReader srDecrypt = new StreamReader(csDecrypt))
          {
            return srDecrypt.ReadToEnd();
          }
        }
      }
    }
  }

}
