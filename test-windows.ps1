param(
    [switch]$Test,
    [switch]$NoBuild,
    [int]$MemoryMB = 512,
    [string]$Qemu = "",
    [string]$Only = "",
    [ValidateSet("rtl8139", "e1000")]
    [string]$Nic = "rtl8139"
)

$ErrorActionPreference = "Stop"

$DistDir        = Join-Path $PSScriptRoot "distribution"
$KernelElf      = Join-Path $DistDir "apollo.bin"
$QemuKernel     = Join-Path $DistDir "apollo32.elf"
$ProgramSource  = Join-Path $PSScriptRoot "tests\programs"
$ProgramDir     = Join-Path $DistDir "programs"
$BootModules    = @("flat.bin", "linux.elf", "windows.exe", "windows_cpp.exe", "acc_native.c")
$FallbackQemu   = "E:\qemu\qemu-system-x86_64.exe"
$MonitorPort    = 45454
$BootTimeoutSec = 60
$StepTimeoutSec = 20
$PollMs         = 500
$KeyDelayMs     = 60
$ScreenAddress  = "0xb8000"
$ScreenCols     = 80
$ScreenRows     = 25
$Prompt         = "apollo> "
$HostHttpPort   = 45480
$EchoHostPort   = 45481
$GuestEchoPort  = 7
$HostBody       = "apollo-host-ok`n"
$NicPatterns    = @{ rtl8139 = '10EC:8139\s+rtl8139'; e1000 = '8086:100E\s+e1000' }

$NetUp = @("networkfix", 'expect:^5\. Gateway answers ARP: ok$', "clear")

# each check types one command on a cleared screen and looks for a line matching the pattern
$Checks = @(
    @{ Name = "echo";            Commands = @("echo apollo test 42");           Expect = '^apollo test 42\s*$' },
    @{ Name = "calc add";        Commands = @("calc 15 + 25");                  Expect = 'Result: 15 \+ 25 = 40\s*$' },
    @{ Name = "calc left fold";  Commands = @("calc 100 * 5 / 2");              Expect = 'Result: 100 \* 5 / 2 = 250\s*$' },
    @{ Name = "mkdir cd pwd";    Commands = @("mkdir wintest", "cd wintest", "pwd"); Expect = '^/?(.*/)?wintest\s*$' },
    @{ Name = "rmdir";           Commands = @("cd /", "mkdir fsx", "rmdir fsx"); Expect = "^Directory 'fsx' removed successfully\.$" },
    @{ Name = "unknown command"; Commands = @("nosuchcmd");                     Expect = '^Unknown command: nosuchcmd\s*$' },
    @{ Name = "driverinfo";      Commands = @("driverinfo");                    Expect = "^\S+\s+$($NicPatterns[$Nic])\s+bound to eth0" },
    @{ Name = "hda bound";       Commands = @("driverinfo");                    Expect = '^\S+\s+8086:2668\s+hda\s+bound, codecs: [1-9]' },
    @{ Name = "uptime sane";     Commands = @("uptime");                        Expect = '^Uptime: 0 hours, [0-9] minutes, \d+ seconds$' },
    @{ Name = "networkfix runs"; Commands = @("networkfix");                    Expect = '^\d\. .*: (ok|failed)$' },
    @{ Name = "network up";      Commands = @("networkfix");                    Expect = '^5\. Gateway answers ARP: ok$' },
    @{ Name = "ping gateway";    Commands = $NetUp + @("ping 10.0.2.2 2");     Expect = '^2 sent, 2 received, 0% loss, rtt min/avg/max \d+/\d+/\d+ ms$' },
    @{ Name = "traceroute";      Commands = $NetUp + @("traceroute 10.0.2.2"); Expect = '^1   10\.0\.2\.2  \d+ ms$' },
    @{ Name = "nslookup";        Commands = $NetUp + @("nslookup example.com"); Expect = '^Address: \d+\.\d+\.\d+\.\d+$' },
    @{ Name = "wget host";       Commands = $NetUp + @("wget http://10.0.2.2:$HostHttpPort/", 'expect:^HTTP 200, 15 bytes of body$');
                                 Expect = '^apollo-host-ok$' },
    @{ Name = "telnet host";     Commands = $NetUp + @("telnet 10.0.2.2 $HostHttpPort", 'expect:^Connected, press Esc to close$',
                                     "type:get / http/1.0", "keys:ret", "keys:ret", 'expect:^apollo-host-ok$');
                                 Expect = '^Connection closed by the remote host$' },
    @{ Name = "tcpdump syn";     Commands = $NetUp + @("tcpdump 1", 'expect:^Capturing on all interfaces', "hostsyn:");
                                 Expect = "^\d+ in  IP 10\.0\.2\.2 > 10\.0\.2\.15 TCP \d+ > $GuestEchoPort \[S\] len \d+$" },
    @{ Name = "listen echo";     Commands = $NetUp + @("listen $GuestEchoPort", 'expect:^Echo service listening on TCP port', "hostecho:apollo echo");
                                 Expect = "^Echo service listening on TCP port $GuestEchoPort$" },
    @{ Name = "netstat listen";  Commands = @("netstat");                       Expect = "^tcp\s+0\.0\.0\.0:$GuestEchoPort\s+0\.0\.0\.0:0\s+LISTEN$" },
    @{ Name = "route add";       Commands = @("route add 192.168.50.0/24 10.0.2.2", "route show");
                                 Expect = '^192\.168\.50\.0\s+255\.255\.255\.0\s+10\.0\.2\.2\s+eth0\s+static$' },
    @{ Name = "route del";       Commands = @("route del 192.168.50.0/24");     Expect = '^Route deleted$' },
    @{ Name = "arp clear";       Commands = @("arp clear", "arp show");         Expect = '^\(empty\)$' },
    @{ Name = "boot modules";    Commands = @("ls /boot");                      Expect = 'windows_cpp\.exe' },
    @{ Name = "flat binary";     Commands = @("run /boot/flat.bin", 'expect:^flat binary ok$'); Expect = '^Exit code: 7$' },
    @{ Name = "linux static";    Commands = @("cd /home", "run /boot/linux.elf files", 'expect:^argc=2 mode=files$',
                                     'expect:^read back: second 42$', 'expect:^empty directory entries: 2$',
                                     'expect:^malloc last byte: 7$', 'expect:^float: 6\.283$', 'expect:^usr1 handled: 1$',
                                     'expect:^recovered from SIGSEGV$', 'expect:^slept at least 200 ms: yes$',
                                     'expect:^name\?$', "apollo", 'expect:^hello apollo$');
                                 Expect = '^Exit code: 5$' },
    @{ Name = "linux fault";     Commands = @("run /boot/linux.elf fault", 'expect:^Program fault: page fault at address 0x10, rip 0x');
                                 Expect = '^Exit code: 139$' },
    @{ Name = "linux abort";     Commands = @("run /boot/linux.elf abort", 'expect:^Aborted$'); Expect = '^Exit code: 134$' },
    @{ Name = "linux ctrl-c";    Commands = @("run /boot/linux.elf spin", 'expect:^spinning$', "keys:ctrl-c", 'expect:^\^C$');
                                 Expect = '^Exit code: 130$' },
    @{ Name = "windows exe";     Commands = @("cd /home", "run /boot/windows.exe files", 'expect:^argc=2 mode=files$',
                                     'expect:^read back: x 5$', 'expect:^text mode size: 5$', 'expect:^removed: yes$',
                                     'expect:^rand after srand\(1\): 41$', 'expect:^name\?$', "apollo", 'expect:^hello apollo$');
                                 Expect = '^Exit code: 3$' },
    @{ Name = "windows seh";     Commands = @("run /boot/windows.exe seh", 'expect:^caught access violation$',
                                     'expect:^caught 0xE0000001$', 'expect:^in try$', 'expect:^finally ran$');
                                 Expect = '^Exit code: 0$' },
    @{ Name = "windows fault";   Commands = @("run /boot/windows.exe fault", 'expect:^Unhandled exception 0xC0000005 \(access violation\)');
                                 Expect = '^Exit code: -1073741819 \(0xC0000005\)$' },
    @{ Name = "windows c++";     Commands = @("run /boot/windows_cpp.exe", 'expect:^destructor ran$',
                                     'expect:^caught: thrown through a frame$', 'expect:^line\?$', "words", 'expect:^got words$');
                                 Expect = '^Exit code: 0$' },
    @{ Name = "acc bytecode";    Commands = @("acc /boot/acc_native.c /home/ab.o", "run /home/ab.o", 'expect:^fib 6765 sum 123$',
                                     'expect:^\[   42\] \[42   \] \[00042\] \[ff\] \[FF\] \[A\] \[str\] \[4294967295\]$');
                                 Expect = '^Exit code: 61$' },
    @{ Name = "acc native";      Commands = @("acc -native /boot/acc_native.c /home/an.elf", "run /home/an.elf", 'expect:^fib 6765 sum 123$',
                                     'expect:^\[   42\] \[42   \] \[00042\] \[ff\] \[FF\] \[A\] \[str\] \[4294967295\]$');
                                 Expect = '^Exit code: 61$' },
    @{ Name = "crypto self-test"; Commands = @("crypto test");                  Expect = '^Cryptographic self-test PASSED$' },
    @{ Name = "sha256 abc";      Commands = @("crypto hash abc");               Expect = "^SHA-256\('abc'\) = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015a" },
    @{ Name = "aes round trip";  Commands = @("crypto aes apollo");             Expect = '^Round trip: match$' },
    @{ Name = "secure boot reference"; Commands = @("secureboot status");       Expect = '^Kernel reference: match$' },
    @{ Name = "secure boot self-test"; Commands = @("secureboot test");         Expect = '^SECURE BOOT SELF-TEST PASSED$' },
    @{ Name = "firewall rule";   Commands = @("firewall enable", "firewall add in deny udp 5353", "firewall rules"); Expect = '^\d+\s+yes\s+in\s+udp\s+5353\s+DENY\s+0\s+Added from shell$' },
    @{ Name = "ratelimit rule";  Commands = @("ratelimit port 80 50", "ratelimit rules"); Expect = '^\d+\s+per-port\s+80\s+50\s+25\s+0\s+Port rate limit$' },
    @{ Name = "security audit";  Commands = @("secaudit --quick");              Expect = '^Result: (PASSED|FAILED)$' },
    @{ Name = "audio tone";      Commands = @("audiotone 440 1");               Expect = '^Played 48000 of 48000 frames$' },
    @{ Name = "ps tasks";        Commands = @("ps");                            Expect = '^1\s+(ready|running)\s+system\s+\d+\s+-\s+shell$' },
    @{ Name = "acc sample";      Commands = @("acc /home/sample.c /home/sample.o", "exec /home/sample.o"); Expect = '^Exit code: 0$' },
    @{ Name = "acc file output"; Commands = @("cat /tmp/output.txt");          Expect = '^File I/O works!$' },
    @{ Name = "acc program";     Commands = @("edit /home/t.c",
        "type:int fib(int n) { if (n < 2) return n; return fib(n - 1) + fib(n - 2); }", "keys:ret",
        "type:int main(void) { int a[5]; int s = 0;", "keys:ret",
        "type:for (int i = 0; i < 5; i++) { a[i] = i * i; s += a[i]; }", "keys:ret",
        "type:printf(""fib=%d sum=%d hex=%x\n"", fib(15), s, 255); return s; }", "keys:ret",
        "keys:f2", "keys:f3", "expect:^apollo>",
        "acc /home/t.c /home/t.o", "exec /home/t.o"); Expect = '^fib=610 sum=30 hex=ff$' },
    @{ Name = "acc exit code";   Commands = @("exec /home/t.o");               Expect = '^Exit code: 30$' },
    @{ Name = "acc runtime error"; Commands = @("edit /home/z.c", "type:int main(void) { int z = 0; return 5 / z; }",
        "keys:f2", "keys:f3", "expect:^apollo>", "acc /home/z.c /home/z.o", "exec /home/z.o");
        Expect = 'runtime error at 0x[0-9a-f]{4}: division by zero$' },
    @{ Name = "acc compile error"; Commands = @("edit /home/e.c", "type:int main(void) { return x; }",
        "keys:f2", "keys:f3", "expect:^apollo>", "acc /home/e.c /home/e.o");
        Expect = "^Compilation failed: line 1: undeclared identifier 'x'$" },
    @{ Name = "editor typing";Commands = @("edit wintest.txt", "type:int x = 42;", "expect:^  1: int x = 42;$", "expect:Ln:1 Col:12 ", "keys:f3", "keys:n"); Expect = '^apollo>$' }
)

# QEMU key names for the characters the checks type. Keypad keys avoid needing shift.
$KeyNames = @{
    ' ' = "spc"; '+' = "kp_add"; '*' = "kp_multiply"; '/' = "slash"
    '-' = "minus"; '.' = "dot"; '=' = "equal"; ',' = "comma"; ';' = "semicolon"
    '[' = "bracket_left"; ']' = "bracket_right"; "'" = "apostrophe"; '\' = "backslash"
    '{' = "shift-bracket_left"; '}' = "shift-bracket_right"; '(' = "shift-9"; ')' = "shift-0"
    '"' = "shift-apostrophe"; '<' = "shift-comma"; '>' = "shift-dot"; '%' = "shift-5"; '!' = "shift-1"
    '&' = "shift-7"; '|' = "shift-backslash"; '_' = "shift-minus"; ':' = "shift-semicolon"
    '#' = "shift-3"; '?' = "shift-slash"; '^' = "shift-6"; '~' = "shift-grave_accent"
}

function Write-Step([string]$text) {
    Write-Host "== $text" -ForegroundColor Cyan
}

function Find-Tool([string]$name, [string]$fallback) {
    $found = Get-Command $name -ErrorAction SilentlyContinue
    if ($found) { return $found.Source }
    if ($fallback -and (Test-Path $fallback)) { return $fallback }
    throw "$name was not found. Put it on PATH."
}

function Find-Qemu {
    if ($Qemu) { return $Qemu }
    return Find-Tool "qemu-system-x86_64" $FallbackQemu
}

# the Makefile recipes use mkdir -p, so make needs a POSIX sh
function Add-ShToPath {
    if (Get-Command "sh" -ErrorAction SilentlyContinue) { return }
    $git = Get-Command "git" -ErrorAction SilentlyContinue
    if ($git) {
        $usrBin = Join-Path (Split-Path (Split-Path $git.Source)) "usr\bin"
        if (Test-Path (Join-Path $usrBin "sh.exe")) {
            $env:PATH = "$usrBin;$env:PATH"
            return
        }
    }
    throw "sh was not found. Install Git for Windows or put sh.exe on PATH."
}

# QEMU only loads 32 bit multiboot ELF files, so the 64 bit kernel is rewrapped as elf32.
function Build-Kernel {
    Write-Step "Building the kernel"
    Add-ShToPath
    $null = Find-Tool "clang" ""
    $null = Find-Tool "ld.lld" ""
    $null = Find-Tool "nasm" ""
    $null = Find-Tool "llvm-objcopy" ""
    # Compiler warnings go to stderr, which PS 5.1 turns into errors under Stop
    Push-Location $PSScriptRoot
    $ErrorActionPreference = "Continue"
    try {
        & make kernel "CROSS_COMPILER=clang --target=x86_64-elf" "LINKER=ld.lld" "OBJCOPY=llvm-objcopy" 2>&1 | ForEach-Object { "$_" }
        if ($LASTEXITCODE -ne 0) { throw "The kernel build failed with exit code $LASTEXITCODE." }
    } finally {
        $ErrorActionPreference = "Stop"
        Pop-Location
    }
    $objcopy = Find-Tool "llvm-objcopy" ""
    & $objcopy -I elf64-x86-64 -O elf32-i386 $KernelElf $QemuKernel
    if ($LASTEXITCODE -ne 0) { throw "Converting the kernel to elf32 failed with exit code $LASTEXITCODE." }
}

function Build-Programs {
    Write-Step "Building the test programs"
    New-Item -ItemType Directory -Force $ProgramDir | Out-Null
    $nasm = Find-Tool "nasm" ""
    & $nasm -f bin (Join-Path $ProgramSource "flat.asm") -o (Join-Path $ProgramDir "flat.bin")
    if ($LASTEXITCODE -ne 0) { throw "Assembling flat.asm failed with exit code $LASTEXITCODE." }
    $clang = Find-Tool "clang" ""
    # Without async exceptions clang leaves faulting instructions outside __try ranges, as on Windows
    & $clang -O1 -fasync-exceptions -D_CRT_SECURE_NO_WARNINGS (Join-Path $ProgramSource "windows.c") -o (Join-Path $ProgramDir "windows.exe")
    if ($LASTEXITCODE -ne 0) { throw "Building windows.exe failed with exit code $LASTEXITCODE." }
    $clangxx = Find-Tool "clang++" ""
    & $clangxx -O1 (Join-Path $ProgramSource "windows_cpp.cpp") -o (Join-Path $ProgramDir "windows_cpp.exe")
    if ($LASTEXITCODE -ne 0) { throw "Building windows_cpp.exe failed with exit code $LASTEXITCODE." }
    $wsl = Find-Tool "wsl" ""
    $source = (& $wsl wslpath -a (Join-Path $ProgramSource "linux.c")).Trim()
    $target = (& $wsl wslpath -a (Join-Path $ProgramDir "linux.elf")).Trim()
    & $wsl -e gcc -static -O2 $source -o $target
    if ($LASTEXITCODE -ne 0) { throw "Building linux.elf with gcc in WSL failed with exit code $LASTEXITCODE." }
    Copy-Item (Join-Path $ProgramSource "acc_native.c") $ProgramDir
}

function Get-QemuArgs {
    return @(
        "-initrd", ($BootModules -join ","),
        "-kernel", $QemuKernel,
        "-m", "${MemoryMB}M",
        "-no-reboot",
        "-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:${EchoHostPort}-:${GuestEchoPort}",
        "-device", "$Nic,netdev=net0",
        "-device", "intel-hda"
    )
}

function Start-Window {
    $qemuExe = Find-Qemu
    $qemuArgs = (Get-QemuArgs) + @("-device", "hda-duplex", "-name", "Apollo")
    Write-Step "Starting Apollo in a QEMU window"
    Write-Host "Click inside the window to type. Ctrl+Alt+G releases the mouse."
    Write-Host "The test programs are in /boot, try: run /boot/windows.exe"
    Push-Location $ProgramDir
    try { & $qemuExe @qemuArgs } finally { Pop-Location }
}

function Connect-Monitor([System.Diagnostics.Process]$proc) {
    $deadline = (Get-Date).AddSeconds($StepTimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if ($proc.HasExited) { throw "QEMU exited with code $($proc.ExitCode) before the monitor opened." }
        try {
            $client = New-Object System.Net.Sockets.TcpClient("127.0.0.1", $MonitorPort)
            $monitor = @{
                Client = $client
                Stream = $client.GetStream()
                Writer = New-Object System.IO.StreamWriter($client.GetStream())
            }
            $monitor.Writer.AutoFlush = $true
            $null = Read-MonitorReply $monitor
            return $monitor
        } catch [System.Net.Sockets.SocketException] {
            Start-Sleep -Milliseconds $PollMs
        }
    }
    throw "Could not connect to the QEMU monitor on port $MonitorPort."
}

# Reads until the monitor prints its prompt again, which marks the end of a reply
function Read-MonitorReply($monitor) {
    $buffer = New-Object System.Text.StringBuilder
    $bytes = New-Object byte[] 65536
    $deadline = (Get-Date).AddSeconds($StepTimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if ($monitor.Stream.DataAvailable) {
            $count = $monitor.Stream.Read($bytes, 0, $bytes.Length)
            [void]$buffer.Append([System.Text.Encoding]::ASCII.GetString($bytes, 0, $count))
            if ($buffer.ToString().EndsWith("(qemu) ")) { return $buffer.ToString() }
        } else {
            Start-Sleep -Milliseconds 20
        }
    }
    throw "The QEMU monitor did not answer within $StepTimeoutSec seconds."
}

function Invoke-Monitor($monitor, [string]$command) {
    $monitor.Writer.Write("$command`n")
    return Read-MonitorReply $monitor
}

# Dumps VGA text memory and keeps the low byte of each cell, which is the character
function Read-Screen($monitor) {
    $cells = $ScreenCols * $ScreenRows
    $reply = Invoke-Monitor $monitor "xp /${cells}xh $ScreenAddress"
    $chars = New-Object System.Text.StringBuilder
    foreach ($line in ($reply -split "`r?`n")) {
        if ($line -notmatch '^[0-9a-f]+:\s') { continue }
        foreach ($m in [regex]::Matches($line.Substring($line.IndexOf(':')), '0x([0-9a-f]{4})')) {
            $code = [Convert]::ToInt32($m.Groups[1].Value, 16) -band 0xFF
            if ($code -lt 32 -or $code -gt 126) { $code = 32 }
            [void]$chars.Append([char]$code)
        }
    }
    $text = $chars.ToString()
    if ($text.Length -ne $cells) { throw "Read $($text.Length) screen cells, expected $cells." }
    $rows = @()
    for ($row = 0; $row -lt $ScreenRows; $row++) {
        $rows += $text.Substring($row * $ScreenCols, $ScreenCols).TrimEnd()
    }
    return $rows
}

function Send-Keys($monitor, [string[]]$keys) {
    foreach ($key in $keys) {
        $null = Invoke-Monitor $monitor "sendkey $key"
        Start-Sleep -Milliseconds $KeyDelayMs
    }
}

function Send-Text($monitor, [string]$text) {
    $keys = foreach ($ch in $text.ToCharArray()) {
        $key = $KeyNames[[string]$ch]
        if (-not $key) {
            if ($ch -notmatch '[a-z0-9]') { throw "No key mapping for '$ch'." }
            $key = [string]$ch
        }
        $key
    }
    Send-Keys $monitor $keys
}

function Send-Line($monitor, [string]$text) {
    Send-Text $monitor $text
    Send-Keys $monitor @("ret")
}

function Wait-Screen($monitor, [System.Diagnostics.Process]$proc, [string]$pattern, [int]$timeoutSec) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    $rows = @()
    while ((Get-Date) -lt $deadline) {
        if ($proc.HasExited) { return @{ Found = $false; Rows = $rows; Exited = $true } }
        $rows = Read-Screen $monitor
        if ($rows | Where-Object { $_ -match $pattern }) { return @{ Found = $true; Rows = $rows; Exited = $false } }
        Start-Sleep -Milliseconds $PollMs
    }
    return @{ Found = $false; Rows = $rows; Exited = $false }
}

function Wait-Prompt($monitor, [System.Diagnostics.Process]$proc, [int]$timeoutSec) {
    return Wait-Screen $monitor $proc ('^' + [regex]::Escape($Prompt.TrimEnd()) + '$') $timeoutSec
}

# Answers every connection with a fixed HTTP response once the request headers end
function Start-HostServer {
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $HostHttpPort)
    $listener.Start()
    $shell = [powershell]::Create()
    $null = $shell.AddScript({
        param($listener, $body)
        $response = [System.Text.Encoding]::ASCII.GetBytes(
            "HTTP/1.0 200 OK`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n$body")
        while ($true) {
            try { $client = $listener.AcceptTcpClient() } catch { break }
            try {
                $stream = $client.GetStream()
                $stream.ReadTimeout = 10000
                $seen = ""
                while (-not $seen.EndsWith("`r`n`r`n")) {
                    $b = $stream.ReadByte()
                    if ($b -lt 0) { break }
                    $seen += [char]$b
                }
                $stream.Write($response, 0, $response.Length)
            } catch {
            } finally {
                $client.Close()
            }
        }
    }).AddArgument($listener).AddArgument($HostBody)
    $handle = $shell.BeginInvoke()
    return @{ Listener = $listener; Shell = $shell; Handle = $handle }
}

function Stop-HostServer($server) {
    $server.Listener.Stop()
    $null = $server.Handle.AsyncWaitHandle.WaitOne(2000)
    $server.Shell.Dispose()
}

# Sends a line through the hostfwd port and checks the guest sends the same bytes back
function Invoke-HostEcho($monitor, [string]$text) {
    $reply = ""
    try {
        $client = New-Object System.Net.Sockets.TcpClient("127.0.0.1", $EchoHostPort)
        $stream = $client.GetStream()
        $stream.ReadTimeout = $StepTimeoutSec * 1000
        $bytes = [System.Text.Encoding]::ASCII.GetBytes("$text`n")
        $stream.Write($bytes, 0, $bytes.Length)
        $buffer = New-Object byte[] 256
        while ($reply.Length -lt $bytes.Length) {
            $n = $stream.Read($buffer, 0, $buffer.Length)
            if ($n -le 0) { break }
            $reply += [System.Text.Encoding]::ASCII.GetString($buffer, 0, $n)
        }
        $client.Close()
    } catch {
        $reply = "error: $($_.Exception.Message)"
    }
    $rows = Read-Screen $monitor
    if ($reply -eq "$text`n") { return @{ Found = $true; Rows = $rows; Exited = $false } }
    return @{ Found = $false; Rows = $rows + @("host sent '$text', received '$($reply.TrimEnd())'"); Exited = $false }
}

# Opens and drops a connection through the hostfwd port so the guest sees a SYN
function Send-HostSyn {
    try {
        $client = New-Object System.Net.Sockets.TcpClient("127.0.0.1", $EchoHostPort)
        $client.Close()
    } catch {
    }
}

function Show-Screen([string[]]$rows) {
    $rows | Where-Object { $_ } | ForEach-Object { Write-Host "   | $_" -ForegroundColor DarkGray }
}

function Invoke-Check($monitor, [System.Diagnostics.Process]$proc, $check) {
    Send-Line $monitor "clear"
    $ready = Wait-Prompt $monitor $proc $StepTimeoutSec
    if (-not $ready.Found) { return $ready }
    foreach ($command in $check.Commands) {
        if ($command.StartsWith("type:")) {
            Send-Text $monitor $command.Substring(5)
        } elseif ($command.StartsWith("keys:")) {
            Send-Keys $monitor ($command.Substring(5) -split ' ')
        } elseif ($command.StartsWith("expect:")) {
            $step = Wait-Screen $monitor $proc $command.Substring(7) $StepTimeoutSec
            if (-not $step.Found) { return $step }
        } elseif ($command.StartsWith("hostecho:")) {
            $step = Invoke-HostEcho $monitor $command.Substring(9)
            if (-not $step.Found) { return $step }
        } elseif ($command -eq "hostsyn:") {
            Send-HostSyn
        } else {
            Send-Line $monitor $command
        }
    }
    $result = Wait-Screen $monitor $proc $check.Expect $StepTimeoutSec
    if ($result.Found) {
        $result = Wait-Prompt $monitor $proc $StepTimeoutSec
    }
    return $result
}

function Invoke-Tests {
    $qemuExe = Find-Qemu
    $qemuArgs = (Get-QemuArgs) + @(
        "-audiodev", "none,id=snd0", "-device", "hda-duplex,audiodev=snd0",
        "-display", "none", "-monitor", "tcp:127.0.0.1:$MonitorPort,server,nowait"
    )
    $quoted = $qemuArgs | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } }
    Write-Step "Booting Apollo headless under QEMU"
    $proc = Start-Process -FilePath $qemuExe -ArgumentList $quoted -PassThru -WindowStyle Hidden -WorkingDirectory $ProgramDir
    $passed = 0
    $failed = 0
    $monitor = $null
    $server = Start-HostServer
    try {
        $monitor = Connect-Monitor $proc
        $boot = Wait-Prompt $monitor $proc $BootTimeoutSec
        $bootErrors = $boot.Rows | Where-Object { $_ -match 'CRITICAL ERROR|FATAL' }
        if (-not $boot.Found -or $bootErrors) {
            Write-Host "[FAIL] boot" -ForegroundColor Red
            if ($boot.Exited) { Write-Host "   QEMU exited with code $($proc.ExitCode)" -ForegroundColor Red }
            Show-Screen $boot.Rows
            return $false
        }
        Write-Host "[PASS] boot" -ForegroundColor Green

        foreach ($check in $Checks) {
            $result = Invoke-Check $monitor $proc $check
            if ($result.Found) {
                $passed++
                Write-Host "[PASS] $($check.Name)" -ForegroundColor Green
                continue
            }
            $failed++
            Write-Host "[FAIL] $($check.Name)" -ForegroundColor Red
            if ($result.Exited) {
                Write-Host "   QEMU exited with code $($proc.ExitCode)" -ForegroundColor Red
                break
            }
            Show-Screen $result.Rows
        }
    } finally {
        if ($monitor) { $monitor.Client.Close() }
        if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
        Stop-HostServer $server
    }

    Write-Host "$passed passed, $failed failed, $($Checks.Count) checks"
    return ($passed -eq $Checks.Count)
}

# Runs only the checks whose name matches, for working on one area at a time
if ($Only) { $Checks = @($Checks | Where-Object { $_.Name -match $Only }) }

if (-not $NoBuild) { Build-Kernel; Build-Programs }
if (-not (Test-Path $QemuKernel)) { throw "There is no kernel at $QemuKernel. Run without -NoBuild." }
foreach ($module in $BootModules) {
    if (-not (Test-Path (Join-Path $ProgramDir $module))) { throw "There is no $module in $ProgramDir. Run without -NoBuild." }
}

if (-not $Test) {
    Start-Window
    exit 0
}

if (Invoke-Tests) {
    Write-Host "PASS" -ForegroundColor Green
    exit 0
}
Write-Host "FAIL" -ForegroundColor Red
exit 1