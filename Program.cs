using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;

class PasswordGenerator
{
  static void Main(string[] args)
  {
    try
    {
      Console.Clear();
      Console.WriteLine("------------------------------");
      Console.WriteLine("   🌟 Password Generator 🌟");
      Console.WriteLine("------------------------------");

      if (args.Contains("--help") || args.Contains("-h"))
      {
        DisplayHelp();
        return;
      }

      if (args.Contains("--show") || args.Contains("-s"))
      {
        ShowPasswordsFromFile();
        return;
      }

      SecureString encryptionKey = GetSecureString("🔐 Enter master password: ");

      Console.Write("🆔 Enter a name for the password: ");
      string passwordName = Console.ReadLine();

      int? length = GetIntArgumentValue(args, "length") ?? GetPositiveIntegerInput("📏 Enter password length: ");
      bool? includeUppercase = GetBoolArgumentValue(args, "uppercase") ?? GetYesNoAnswer("🔠 Include uppercase letters?");
      bool? includeNumbers = GetBoolArgumentValue(args, "numbers") ?? GetYesNoAnswer("🔢 Include numbers?");
      bool? includeSpecialChars = GetBoolArgumentValue(args, "special") ?? GetYesNoAnswer("🌟 Include special characters?");
      string excludedChars = GetStringArgumentValue(args, "exclude") ?? GetStringInput("Exclude specific characters (if none, press Enter): ");

      AnimateLoader();

      string generatedPassword = GeneratePassword(length.Value, includeUppercase.Value, includeNumbers.Value, includeSpecialChars.Value, excludedChars);
      bool savePassword = GetYesNoAnswer("💾 Save generated password?");
      if (savePassword)
      {
        PasswordStorage.SavePassword(passwordName, generatedPassword, encryptionKey);
      }

      Console.WriteLine($"\n✨ Generated Password: {FormatText(generatedPassword, ConsoleColor.Cyan)}");
    }
    catch (Exception ex)
    {
      Console.WriteLine($"An error occured: {ex.Message}");
    }
  }

  static void ShowPasswordsFromFile()
  {
    SecureString encryptionKey = GetSecureString("🔐 Enter master password: ");

    // Charger tous les mots de passe depuis le fichier par défaut
    Dictionary<string, string> loadedPasswords = PasswordStorage.LoadPasswords(encryptionKey);

    // Afficher les mots de passe
    if (loadedPasswords.Count > 0)
    {
      Console.WriteLine($"Loaded Passwords:");

      foreach (var entry in loadedPasswords)
      {
        Console.WriteLine($"{entry.Key}: {entry.Value}");
      }
    }
    else
    {
      Console.WriteLine($"No passwords found in the default file 'encrypted_passwords.txt'.");
    }
  }



  static int? GetIntArgumentValue(string[] args, string key)
  {
    int index = Array.IndexOf(args, $"--{key}");
    if (index != -1 && index < args.Length - 1 && int.TryParse(args[index + 1], out int result))
    {
      return result;
    }
    return null;
  }

  static void DisplayHelp()
  {
    Console.WriteLine("Usage:");
    Console.WriteLine("   PasswordGenerator --length <value> --uppercase <value> --numbers <value> --special <value> --exclude <value>");
    Console.WriteLine("\nOptions:");
    Console.WriteLine("   --length     : Length of the password (integer)");
    Console.WriteLine("   --uppercase  : Include uppercase letters (true/false)");
    Console.WriteLine("   --numbers    : Include numbers (true/false)");
    Console.WriteLine("   --special    : Include special characters (true/false)");
    Console.WriteLine("   --exclude    : Exclude specific characters (string)");
  }

  static int GetPositiveIntegerInput(string prompt)
  {
    int value;
    do
    {
      Console.Write(prompt);
    } while (!int.TryParse(Console.ReadLine(), out value) || value <= 0);

    return value;
  }

  static bool GetYesNoAnswer(string question)
  {
    Console.Write($"{question} (Y/N): ");
    ConsoleKeyInfo key;
    do
    {
      key = Console.ReadKey(true);
    } while (key.Key != ConsoleKey.Y && key.Key != ConsoleKey.N);

    Console.WriteLine(key.Key == ConsoleKey.Y ? "✅" : "❌");
    return key.Key == ConsoleKey.Y;
  }


  private static SecureString GetSecureString(string prompt)
  {
    SecureString secureString = new SecureString();
    Console.Write(prompt);
    ConsoleKeyInfo key;  // Retrieves a secure string input from the user with a specified prompt.
      
    do
    {
      key = Console.ReadKey(true);
      if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
      {
        secureString.AppendChar(key.KeyChar);
        Console.Write("*");
      }
      else if (key.Key == ConsoleKey.Backspace && secureString.Length > 0)
      {
        secureString.RemoveAt(secureString.Length - 1);
        Console.Write("\b \b");
      }
    } while (key.Key != ConsoleKey.Enter);
    Console.WriteLine(); // Move to the next line after input
    secureString.MakeReadOnly();
    return secureString;
  }

  static string GetStringInput(string prompt)
  {
    Console.Write(prompt);
    return Console.ReadLine();
  }

  static bool? GetBoolArgumentValue(string[] args, string key)
  {
    int index = Array.IndexOf(args, $"--{key}");
    if (index != -1 && index < args.Length - 1)
    {
      return ParseYesNo(args[index + 1]);
    }
    return null;
  }

  static bool? ParseYesNo(string value)
  {
    value = value.ToLower();
    return value == "true" || value == "yes" ? true : value == "false" || value == "no" ? false : (bool?)null;
  }

  static string? GetStringArgumentValue(string[] args, string key)
  {
    int index = Array.IndexOf(args, $"--{key}");
    if (index != -1 && index < args.Length - 1)
    {
      return args[index + 1];
    }
    return null;
  }

  static void AnimateLoader()
  {
    Console.CursorVisible = false;
    string[] loaderFrames = { "|", "/", "-", "\\" };

    for (int i = 0; i < 10; i++)
    {
      Console.Write($"⚙️ Generating... {FormatText(loaderFrames[i % loaderFrames.Length], ConsoleColor.White)}\r");
      System.Threading.Thread.Sleep(200);
    }

    Console.CursorVisible = true;
    Console.WriteLine("⚙️ Generating... Done.             ");
  }

  static string GeneratePassword(int length, bool includeUppercase, bool includeNumbers, bool includeSpecialChars, string excludedChars)
  {
    string lowercaseChars = "abcdefghijklmnopqrstuvwxyz";
    string uppercaseChars = includeUppercase ? "ABCDEFGHIJKLMNOPQRSTUVWXYZ" : "";
    string numberChars = includeNumbers ? "0123456789" : "";
    string specialChars = includeSpecialChars ? "!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~" : "";

    StringBuilder allChars = new StringBuilder(lowercaseChars + uppercaseChars + numberChars + specialChars);

    if (!string.IsNullOrEmpty(excludedChars))
    {
      foreach (char excludedChar in excludedChars)
      {
        allChars.Replace(excludedChar.ToString(), "");
      }
    }

    StringBuilder password = new StringBuilder();
    using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
    {
      byte[] randomBytes = new byte[length];
      rng.GetBytes(randomBytes);

      for (int i = 0; i < length; i++)
      {
        int index = randomBytes[i] % allChars.Length;
        password.Append(allChars[index]);
      }
    }

    return password.ToString();
  }

  static string FormatText(string text, ConsoleColor color)
  {
    Console.ForegroundColor = color;
    string formattedText = text;
    return formattedText;
  }
}
