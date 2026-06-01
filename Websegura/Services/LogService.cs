using System;
using System.IO;

namespace Websegura.Services
{
    public class LogService
    {
        private readonly string _logPath = "logs/access.log";

        public LogService()
        {
            Directory.CreateDirectory("logs");
        }

        public void Log(string tipo, string usuario, string detalle)
        {
            var entry = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] [{tipo}] Usuario: {usuario} | {detalle}";
            File.AppendAllText(_logPath, entry + Environment.NewLine);
            Console.WriteLine(entry);
        }
    }
}