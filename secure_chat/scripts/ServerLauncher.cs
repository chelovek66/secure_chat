using System;
using System.Diagnostics;
using System.IO;

namespace SecureChat
{
    class ServerLauncher
    {
        static void Main(string[] args)
        {
            Console.Title = "Secure Chat - Server (REST API)";
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string targetExe = Path.Combine(baseDir, "dist", "SecureServer", "SecureServer.exe");

            if (!File.Exists(targetExe))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[ERROR] Не найден исполняемый файл сервера: " + targetExe);
                Console.ResetColor();
                Console.WriteLine("Убедитесь, что папка dist\\SecureServer присутствует.");
                Console.WriteLine("Нажмите любую клавишу для завершения...");
                Console.ReadKey();
                return;
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = targetExe,
                WorkingDirectory = Path.GetDirectoryName(targetExe),
                Arguments = string.Join(" ", args),
                UseShellExecute = false
            };

            try
            {
                using (var process = Process.Start(startInfo))
                {
                    if (process != null)
                    {
                        process.WaitForExit();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[ERROR] Ошибка запуска сервера: " + ex.Message);
                Console.ResetColor();
                Console.WriteLine("Нажмите любую клавишу для завершения...");
                Console.ReadKey();
            }
        }
    }
}
