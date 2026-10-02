using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Diagnostics;
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
        public string? Protocol { get; set; }
        public string? RemoteAddress { get; set; }
        public int? LocalPort { get; set; }
        public int? RemotePort { get; set; }
        public int? NetworkSize { get; set; }
        public ulong? ConnectionId { get; set; }
    }
    class Program
    {
        private const string SessionName = "SyscallMonitorSession";
        private const string OutputPath = "traces.jsonl";

        private static readonly ConcurrentDictionary<ulong, string> _keyNameCache = new();
        private static readonly object _fileLock = new();
        private static StreamWriter? _writer;

        // Filtering: track a process and its children
        private static bool _filterEnabled = false;
        private static int? _filterPid = null;
        private static string? _filterProcessNameLower = null;
        private static readonly ConcurrentDictionary<int, bool> _trackedPids = new();

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

            // parse simple args: --pid=<num> or --process-name=<name>
            foreach (var a in args)
            {
                if (a.StartsWith("--pid=", StringComparison.OrdinalIgnoreCase) &&
                    int.TryParse(a.Substring(6), out var pid))
                {
                    _filterEnabled = true;
                    _filterPid = pid;
                    _trackedPids.TryAdd(pid, true);
                }
                else if (a.StartsWith("--process-name=", StringComparison.OrdinalIgnoreCase))
                {
                    _filterEnabled = true;
                    _filterProcessNameLower = a.Substring("--process-name=".Length).ToLowerInvariant();
                    try
                    {
                        foreach (var p in Process.GetProcesses())
                        {
                            try
                            {
                                if (string.Equals(p.ProcessName, _filterProcessNameLower, StringComparison.OrdinalIgnoreCase) ||
                                    string.Equals((p.ProcessName + ".exe"), _filterProcessNameLower, StringComparison.OrdinalIgnoreCase))
                                {
                                    _trackedPids.TryAdd(p.Id, true);
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
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
                KernelTraceEventParser.Keywords.FileIOInit |
                KernelTraceEventParser.Keywords.NetworkTCPIP);

            Console.WriteLine($"Мониторинг запущен. Запись в {OutputPath}. Нажмите Ctrl + C для остановки.");

            // Process
            session.Source.Kernel.ProcessStart += data =>
            {

                if (_filterEnabled)
                {
                    if (data.ParentID != 0 && _trackedPids.ContainsKey(data.ParentID))
                    {
                        _trackedPids.TryAdd(data.ProcessID, true);
                    }

                    if (!string.IsNullOrEmpty(_filterProcessNameLower) &&
                        !string.IsNullOrEmpty(data.ImageFileName) &&
                        data.ImageFileName.ToLowerInvariant().Contains(_filterProcessNameLower))
                    {
                        _trackedPids.TryAdd(data.ProcessID, true);
                    }

                    if (_filterPid.HasValue && data.ProcessID == _filterPid.Value)
                        _trackedPids.TryAdd(data.ProcessID, true);
                }

                var record = new TraceEventRecord
                {
                    Timestamp = data.TimeStamp.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                    EventType = "ProcessStart",
                    ProcessID = data.ProcessID,
                    ParentProcessID = data.ParentID,
                    ImageFileName = data.ImageFileName
                };


                if (!_filterEnabled || _trackedPids.ContainsKey(record.ProcessID))
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


                if (!_filterEnabled || _trackedPids.ContainsKey(record.ProcessID))
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

            // Network (TCP)
            session.Source.Kernel.TcpIpSend += data =>
                WriteTcpRecord("TcpIpSend", data.daddr, data.sport, data.dport, data.size, data.connid, data);
            session.Source.Kernel.TcpIpRecv += data =>
                WriteTcpRecord("TcpIpRecv", data.daddr, data.sport, data.dport, data.size, data.connid, data);
            session.Source.Kernel.TcpIpConnect += data =>
                WriteTcpRecord("TcpIpConnect", data.daddr, data.sport, data.dport, data.size, data.connid, data);
            session.Source.Kernel.TcpIpDisconnect += data =>
                WriteTcpRecord("TcpIpDisconnect", data.daddr, data.sport, data.dport, data.size, data.connid, data);
            session.Source.Kernel.TcpIpReconnect += data =>
                WriteTcpRecord("TcpIpReconnect", data.daddr, data.sport, data.dport, data.size, data.connid, data);
            session.Source.Kernel.TcpIpRetransmit += data =>
                WriteTcpRecord("TcpIpRetransmit", data.daddr, data.sport, data.dport, data.size, data.connid, data);
            session.Source.Kernel.TcpIpAccept += data =>
                WriteTcpRecord("TcpIpAccept", data.daddr, data.sport, data.dport, data.size, data.connid, data);

            session.Source.Kernel.TcpIpSendIPV6 += data =>
                WriteTcpRecord("TcpIpSend", data.daddr, data.sport, data.dport, data.size, data.connid, data);
            session.Source.Kernel.TcpIpRecvIPV6 += data =>
                WriteTcpRecord("TcpIpRecv", data.daddr, data.sport, data.dport, data.size, data.connid, data);
            session.Source.Kernel.TcpIpConnectIPV6 += data =>
                WriteTcpRecord("TcpIpConnect", data.daddr, data.sport, data.dport, data.size, data.connid, data);
            session.Source.Kernel.TcpIpDisconnectIPV6 += data =>
                WriteTcpRecord("TcpIpDisconnect", data.daddr, data.sport, data.dport, data.size, data.connid, data);
            session.Source.Kernel.TcpIpReconnectIPV6 += data =>
                WriteTcpRecord("TcpIpReconnect", data.daddr, data.sport, data.dport, data.size, data.connid, data);
            session.Source.Kernel.TcpIpRetransmitIPV6 += data =>
                WriteTcpRecord("TcpIpRetransmit", data.daddr, data.sport, data.dport, data.size, data.connid, data);
            session.Source.Kernel.TcpIpAcceptIPV6 += data =>
                WriteTcpRecord("TcpIpAccept", data.daddr, data.sport, data.dport, data.size, data.connid, data);

            session.Source.Process();
            lock (_fileLock)
            {
                _writer?.Flush();
                _writer?.Dispose();
                _writer = null;
            }

            Console.WriteLine("Работа программы корректно завершена.");

        }

        private static void WriteTcpRecord(
            string eventType,
            IPAddress? remoteAddress,
            int localPort,
            int remotePort,
            int size,
            ulong connectionId,
            TraceEvent data)
        {
            var record = new TraceEventRecord
            {
                Timestamp = data.TimeStamp.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                EventType = eventType,
                ProcessID = data.ProcessID,
                Protocol = "TCP",
                RemoteAddress = remoteAddress?.ToString(),
                LocalPort = localPort,
                RemotePort = remotePort,
                NetworkSize = size,
                ConnectionId = connectionId
            };

            WriteRecord(record);
        }

        private static void WriteRecord(TraceEventRecord record)
        {

            if (_filterEnabled && !_trackedPids.ContainsKey(record.ProcessID))
                return;

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
