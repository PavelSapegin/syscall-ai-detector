using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SyscallMonitor
{

    public class TraceEventRecord
    {
        public string Timestamp {get; set;} = "";
        public string EventType {get; set;} = "";
        public int ProcessID {get; set;}
        public int ParentProcessID {get; set;}
        public string ImageFileName {get; set;} = "";
        public int? ExitCode {get; set;}
    }
    class Program
    {
        private const string SessionName = "SyscallMonitorSession";
        private const string OutputPath = "traces.jsonl";

        private static readonly object _fileLock = new();
        private static StreamWriter? _writer;

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

            _writer = new StreamWriter(OutputPath, append: true) {AutoFlush = true};

            using var session = new TraceEventSession(SessionName);

            Console.CancelKeyPress += (s, e) =>
            {
                e.Cancel = true;
                session.Stop();
                _writer?.Flush();
                _writer?.Dispose();
                Console.WriteLine("Сессия оставновлена.");
            };

            session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);

            Console.WriteLine($"Мониторинг запущен. Запись в {OutputPath}. Нажмите Ctrl + C для остановки.");

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

                Console.WriteLine(
                    $"[{record.Timestamp}] START  PID={record.ProcessID,-6} " +
                    $"PPID={record.ParentProcessID,-6} Image={record.ImageFileName}"
                );
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

                Console.WriteLine(
                    $"[{record.Timestamp}] STOP   PID={record.ProcessID,-6} " +
                    $"Image={record.ImageFileName} ExitCode={record.ExitCode}"
                );
            };


            session.Source.Process();
        }

        private static void WriteRecord(TraceEventRecord record)
        {
            string json = JsonSerializer.Serialize(record, _jsonOptions);
            lock (_fileLock)
            {
                _writer?.WriteLine(json);
            }
        }
        
    }    
}
