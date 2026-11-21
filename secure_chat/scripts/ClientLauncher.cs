using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

namespace SecureChat
{
    static class ClientLauncher
    {
        [STAThread]
        static void Main(string[] args)
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string targetExe = Path.Combine(baseDir, "dist", "SecureClient", "SecureClient.exe");

            if (!File.Exists(targetExe))
            {
                MessageBox.Show(
                    "Не найден исполняемый файл клиента:\n" + targetExe + "\n\nУбедитесь, что папка dist\\SecureClient присутствует.",
                    "Secure Chat - Ошибка запуска",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
                return;
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = targetExe,
                WorkingDirectory = Path.GetDirectoryName(targetExe),
                Arguments = string.Join(" ", args),
                UseShellExecute = true
            };

            try
            {
                Process.Start(startInfo);
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    "Не удалось запустить клиент:\n" + ex.Message,
                    "Secure Chat - Ошибка запуска",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
            }
        }
    }
}
