using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace SyscallMonitor
{

    public class TraceEventRecord
    {
        public string Timestamp { get; set; } = "";
        public string EventType { get; set; } = "";
        public int ProcessID { get; set; }
        public int ParentProcessID { get; set; }
        public string ImageFileName { get; set; } = "";
        public int? ExitCode { get; set; }
        public string? KeyName { get; set; }
        public string? ValueName { get; set; }
        public string? FileName { get; set; }
        public long? IoSize { get; set; }
        public long? FileOffset { get; set; }
    }
    class Program
    {
        private const string SessionName = "SyscallMonitorSession";
        private const string OutputPath = "traces.jsonl";

        private static readonly ConcurrentDictionary<ulong, string> _keyNameCache = new();
        private static readonly object _fileLock = new();
        private static StreamWriter? _writer;


        private static readonly Regex _hkeyMachineRegex =
            new(@"^\\?REGISTRY\\MACHINE\\", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static readonly Regex _hkeyUserSidRegex =
            new(@"^\\?REGISTRY\\USER\\(S-1-5-[0-9-]+)\\", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static readonly Regex _hkeyUserDefaultRegex =
            new(@"^\\?REGISTRY\\USER\\\.DEFAULT\\", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static readonly Regex _hkeyWcSiloRegex =
            new(@"^\\?REGISTRY\\WC\\", RegexOptions.IgnoreCase | RegexOptions.Compiled);


        private static string NormalizeRegistryPath(string? rawPath)
        {
            if (string.IsNullOrWhiteSpace(rawPath))
                return "";

            if (_hkeyMachineRegex.IsMatch(rawPath))
                return "HKLM\\" + _hkeyMachineRegex.Replace(rawPath, "");

            var userMatch = _hkeyUserSidRegex.Match(rawPath);
            if (userMatch.Success)
                return $"HKU\\{userMatch.Groups[1].Value}\\" + _hkeyUserSidRegex.Replace(rawPath, "");

            if (_hkeyUserDefaultRegex.IsMatch(rawPath))
                return "HKU\\.DEFAULT\\" + _hkeyUserDefaultRegex.Replace(rawPath, "");

            if (_hkeyWcSiloRegex.IsMatch(rawPath))
                return "HKWC\\" + _hkeyWcSiloRegex.Replace(rawPath, "");

            return rawPath;
        }
        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            WriteIndented = false,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };
        static void Main(string[] args)
        {
            if (!TraceEventSession.IsElevated() ?? false)
            {
                Console.WriteLine("Нужны права администратора. Перезапустите программу от имени Администратора.");
                return;
            }

            _writer = new StreamWriter(OutputPath, append: true) { AutoFlush = true };

            using var session = new TraceEventSession(SessionName);

            Console.CancelKeyPress += (s, e) =>
            {
                e.Cancel = true;
                session.Stop();
            };

            session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.Registry |
                KernelTraceEventParser.Keywords.FileIO |
                KernelTraceEventParser.Keywords.FileIOInit);

            Console.WriteLine($"Мониторинг запущен. Запись в {OutputPath}. Нажмите Ctrl + C для остановки.");

            // Process
            session.Source.Kernel.ProcessStart += data =>
            {
                var record = new TraceEventRecord
                {
                    Timestamp = data.TimeStamp.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                    EventType = "ProcessStart",
                    ProcessID = data.ProcessID,
                    ParentProcessID = data.ParentID,
                    ImageFileName = data.ImageFileName
                };

                WriteRecord(record);
            };

            session.Source.Kernel.ProcessStop += data =>
            {
                var record = new TraceEventRecord
                {
                    Timestamp = data.TimeStamp.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                    EventType = "ProcessStop",
                    ProcessID = data.ProcessID,
                    ParentProcessID = data.ParentID,
                    ImageFileName = data.ImageFileName,
                    ExitCode = data.ExitStatus
                };

                WriteRecord(record);
            };

            // Registry
            session.Source.Kernel.RegistryCreate += data =>
            {
                var record = new TraceEventRecord
                {
                    Timestamp = data.TimeStamp.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                    EventType = "RegistryCreate",
                    ProcessID = data.ProcessID,
                    KeyName = NormalizeRegistryPath(data.KeyName)
                };
                WriteRecord(record);
            };

            session.Source.Kernel.RegistryKCBCreate += data =>
            {
                _keyNameCache[(ulong)data.KeyHandle] = NormalizeRegistryPath(data.KeyName);
            };

            session.Source.Kernel.RegistryKCBRundownEnd += data =>
            {
                _keyNameCache[(ulong)data.KeyHandle] = NormalizeRegistryPath(data.KeyName);
            };

            session.Source.Kernel.RegistrySetValue += data =>
            {
                string resolvedKey = _keyNameCache.TryGetValue((ulong)data.KeyHandle, out var cached)
                    ? cached
                    : data.KeyName;

                var record = new TraceEventRecord
                {
                    Timestamp = data.TimeStamp.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                    EventType = "RegistrySetValue",
                    ProcessID = data.ProcessID,
                    KeyName = NormalizeRegistryPath(resolvedKey),
                    ValueName = data.ValueName
                };
                WriteRecord(record);
            };

            // File I/O
            session.Source.Kernel.FileIOCreate += data =>
            {
                var record = new TraceEventRecord
                {
                    Timestamp = data.TimeStamp.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                    EventType = "FileIOCreate",
                    ProcessID = data.ProcessID,
                    FileName = data.FileName
                };
                WriteRecord(record);
            };

            session.Source.Kernel.FileIOWrite += data =>
            {
                var record = new TraceEventRecord
                {
                    Timestamp = data.TimeStamp.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                    EventType = "FileIOWrite",
                    ProcessID = data.ProcessID,
                    FileName = data.FileName,
                    IoSize = data.IoSize,
                    FileOffset = data.Offset
                };
                WriteRecord(record);
            };

            session.Source.Process();
            lock (_fileLock)
            {
                _writer?.Flush();
                _writer?.Dispose();
                _writer = null;
            }

            Console.WriteLine("Работа программы корректно завершена.");

        }

        private static void WriteRecord(TraceEventRecord record)
        {
            string json = JsonSerializer.Serialize(record, _jsonOptions);
            lock (_fileLock)
            {
                if (_writer != null && _writer.BaseStream != null && _writer.BaseStream.CanWrite)
                {
                    try
                    {
                        _writer.WriteLine(json);
                    }
                    catch (ObjectDisposedException)
                    {

                    }
                }
            }
        }

    }
}
