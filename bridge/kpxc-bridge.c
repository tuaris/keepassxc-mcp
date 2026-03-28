/*
 * kpxc-bridge.c — TCP-to-named-pipe bridge for KeePassXC
 *
 * Forwards TCP connections to the KeePassXC browser integration named pipe,
 * allowing remote clients (e.g., an MCP server in a VM) to communicate with
 * KeePassXC running on this Windows host.
 *
 * Build (Visual Studio Developer Command Prompt):
 *   cl /O2 /W4 kpxc-bridge.c /Fe:kpxc-bridge.exe ws2_32.lib advapi32.lib
 *
 * Build (MinGW / MSYS2):
 *   gcc -O2 -Wall -o kpxc-bridge.exe kpxc-bridge.c -lws2_32 -ladvapi32
 *
 * Build (Zig CC, cross-compile from any OS):
 *   zig cc -O2 -target x86_64-windows-gnu kpxc-bridge.c -lws2_32 -ladvapi32 -o kpxc-bridge.exe
 *
 * Usage:
 *   kpxc-bridge.exe                         Run in console mode (Ctrl+C to stop)
 *   kpxc-bridge.exe -port 19455             Set TCP listen port
 *   kpxc-bridge.exe -bind 192.168.0.1       Bind to specific interface
 *   kpxc-bridge.exe -pipe \\.\pipe\NAME     Override named pipe path
 *   kpxc-bridge.exe install [-port ...] ...  Install as Windows service
 *   kpxc-bridge.exe uninstall               Remove Windows service
 *
 * Service mode reads configuration from registry:
 *   HKLM\SYSTEM\CurrentControlSet\Services\KeePassXCBridge\Parameters
 *     Port        (REG_DWORD)  default 19455
 *     BindAddress (REG_SZ)     default "0.0.0.0"
 *     PipeName    (REG_SZ)     default "\\.\pipe\org.keepassxc.KeePassXC.BrowserServer"
 *
 * Requires: Windows Vista or later. No external dependencies.
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

/* ---------- Defaults ---------- */
#define DEFAULT_PORT    19455
#define DEFAULT_BIND    "0.0.0.0"
#define DEFAULT_PIPE    "\\\\.\\pipe\\org.keepassxc.KeePassXC.BrowserServer"
#define SERVICE_NAME    "KeePassXCBridge"
#define SERVICE_DISPLAY "KeePassXC TCP Bridge"
#define SERVICE_DESC_S  "Bridges TCP connections to the KeePassXC browser integration named pipe"
#define BUFFER_SIZE     65536
#define PIPE_WAIT_MS    5000

/* ---------- Globals ---------- */
static int           g_port = DEFAULT_PORT;
static char          g_bind[64] = DEFAULT_BIND;
static char          g_pipe[256] = DEFAULT_PIPE;
static SOCKET        g_listen_sock = INVALID_SOCKET;
static volatile BOOL g_running = TRUE;
static FILE         *g_logfile = NULL;

/* Service globals */
static SERVICE_STATUS        g_svc_status;
static SERVICE_STATUS_HANDLE g_svc_status_handle;

/* ---------- Logging ---------- */
static void logmsg(const char *fmt, ...)
{
    FILE *f = g_logfile ? g_logfile : stderr;
    va_list ap;
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] ",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond);
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fprintf(f, "\n");
    fflush(f);
}

/* ---------- Per-connection context ---------- */
typedef struct {
    SOCKET        tcp_sock;
    HANDLE        pipe_handle;
    volatile LONG alive;
    HANDLE        h_tcp_to_pipe;   /* thread handle for CancelSynchronousIo */
    HANDLE        h_pipe_to_tcp;   /* thread handle for CancelSynchronousIo */
} ConnCtx;

/*
 * Overlapped helper: issue an async I/O and wait for completion.
 * Returns TRUE on success (bytes transferred stored in *pN), FALSE on error.
 */
static BOOL overlapped_io_read(HANDLE h, void *buf, DWORD bufsize, DWORD *pN,
                               HANDLE hEvent)
{
    OVERLAPPED ov = {0};
    ov.hEvent = hEvent;
    *pN = 0;
    if (ReadFile(h, buf, bufsize, pN, &ov))
        return TRUE;                       /* completed immediately */
    if (GetLastError() != ERROR_IO_PENDING)
        return FALSE;
    /* Wait for the async operation */
    if (!GetOverlappedResult(h, &ov, pN, TRUE))
        return FALSE;
    return TRUE;
}

static BOOL overlapped_io_write(HANDLE h, const void *buf, DWORD len,
                                DWORD *pN, HANDLE hEvent)
{
    OVERLAPPED ov = {0};
    ov.hEvent = hEvent;
    *pN = 0;
    if (WriteFile(h, buf, len, pN, &ov))
        return TRUE;
    if (GetLastError() != ERROR_IO_PENDING)
        return FALSE;
    if (!GetOverlappedResult(h, &ov, pN, TRUE))
        return FALSE;
    return TRUE;
}

/* Forward: TCP -> Named Pipe */
static DWORD WINAPI tcp_to_pipe_thread(LPVOID param)
{
    ConnCtx *ctx = (ConnCtx *)param;
    char buf[BUFFER_SIZE];
    int msg_count = 0;
    HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    while (InterlockedCompareExchange(&ctx->alive, 1, 1)) {
        int n = recv(ctx->tcp_sock, buf, sizeof(buf), 0);
        if (n <= 0) {
            logmsg("tcp->pipe: recv returned %d (WSA %d)", n, WSAGetLastError());
            break;
        }
        msg_count++;
        logmsg("tcp->pipe: recv %d bytes (msg #%d)", n, msg_count);

        DWORD written, total = 0;
        while (total < (DWORD)n) {
            if (!overlapped_io_write(ctx->pipe_handle, buf + total,
                                     (DWORD)n - total, &written, hEvent)) {
                logmsg("tcp->pipe: WriteFile failed: error %lu", GetLastError());
                goto done;
            }
            total += written;
        }
        logmsg("tcp->pipe: wrote %lu bytes to pipe", total);
    }
done:
    logmsg("tcp->pipe: thread exiting (msg_count=%d)", msg_count);
    InterlockedExchange(&ctx->alive, 0);
    /* Cancel the pipe_to_tcp thread's pending ReadFile */
    CancelIoEx(ctx->pipe_handle, NULL);
    CloseHandle(hEvent);
    return 0;
}

/* Forward: Named Pipe -> TCP */
static DWORD WINAPI pipe_to_tcp_thread(LPVOID param)
{
    ConnCtx *ctx = (ConnCtx *)param;
    char buf[BUFFER_SIZE];
    int msg_count = 0;
    HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    while (InterlockedCompareExchange(&ctx->alive, 1, 1)) {
        DWORD n = 0;
        if (!overlapped_io_read(ctx->pipe_handle, buf, sizeof(buf),
                                &n, hEvent) || n == 0) {
            logmsg("pipe->tcp: ReadFile err=%lu n=%lu", GetLastError(), n);
            break;
        }
        msg_count++;
        logmsg("pipe->tcp: read %lu bytes from pipe (msg #%d)", n, msg_count);

        int total = 0;
        while (total < (int)n) {
            int sent = send(ctx->tcp_sock, buf + total, (int)n - total, 0);
            if (sent <= 0) {
                logmsg("pipe->tcp: send failed: WSA %d", WSAGetLastError());
                goto done;
            }
            total += sent;
        }
        logmsg("pipe->tcp: sent %d bytes to TCP", total);
    }
done:
    logmsg("pipe->tcp: thread exiting (msg_count=%d)", msg_count);
    InterlockedExchange(&ctx->alive, 0);
    shutdown(ctx->tcp_sock, SD_BOTH);
    CancelIoEx(ctx->pipe_handle, NULL);
    CloseHandle(hEvent);
    return 0;
}

/* Resolve the actual pipe path — KeePassXC may append _Username */
static const char *resolve_pipe(void)
{
    /* Try the configured name first */
    if (WaitNamedPipeA(g_pipe, 500))
        return g_pipe;

    /* Try with _Username suffix */
    static char suffixed[512];
    char username[128];
    DWORD ulen = sizeof(username);
    if (GetUserNameA(username, &ulen) && ulen > 0) {
        _snprintf(suffixed, sizeof(suffixed), "%s_%s", g_pipe, username);
        if (WaitNamedPipeA(suffixed, 500))
            return suffixed;
    }

    return NULL;
}

/* Handle a single accepted TCP connection */
static DWORD WINAPI handle_connection(LPVOID param)
{
    SOCKET tcp_sock = (SOCKET)(uintptr_t)param;
    HANDLE pipe = INVALID_HANDLE_VALUE;

    /* Wait for the KeePassXC pipe to become available */
    const char *pipe_path = resolve_pipe();
    if (!pipe_path) {
        logmsg("ERROR: Pipe not available (%s or %s_<user>) — is KeePassXC "
               "running with browser integration enabled? (error %lu)",
               g_pipe, g_pipe, GetLastError());
        closesocket(tcp_sock);
        return 1;
    }

    if (strcmp(pipe_path, g_pipe) != 0)
        logmsg("Using pipe: %s", pipe_path);

    pipe = CreateFileA(
        pipe_path,
        GENERIC_READ | GENERIC_WRITE,
        0,             /* no sharing */
        NULL,          /* default security */
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
        NULL);

    if (pipe == INVALID_HANDLE_VALUE) {
        logmsg("ERROR: CreateFile(%s) failed: error %lu", pipe_path, GetLastError());
        closesocket(tcp_sock);
        return 1;
    }

    /* Ensure byte mode (KeePassXC uses QLocalSocket which is byte-oriented) */
    DWORD mode = PIPE_READMODE_BYTE | PIPE_WAIT;
    SetNamedPipeHandleState(pipe, &mode, NULL, NULL);

    logmsg("Pipe connected — forwarding traffic");

    ConnCtx ctx;
    ctx.tcp_sock       = tcp_sock;
    ctx.pipe_handle    = pipe;
    ctx.alive          = 1;
    ctx.h_tcp_to_pipe  = NULL;
    ctx.h_pipe_to_tcp  = NULL;

    HANDLE t1 = CreateThread(NULL, 0, tcp_to_pipe_thread, &ctx, 0, NULL);
    HANDLE t2 = CreateThread(NULL, 0, pipe_to_tcp_thread, &ctx, 0, NULL);
    ctx.h_tcp_to_pipe = t1;
    ctx.h_pipe_to_tcp = t2;

    if (!t1 || !t2) {
        logmsg("ERROR: CreateThread failed: %lu", GetLastError());
        InterlockedExchange(&ctx.alive, 0);
    }

    /* Wait for both forwarding threads to finish */
    if (t1) { WaitForSingleObject(t1, INFINITE); CloseHandle(t1); }
    if (t2) { WaitForSingleObject(t2, INFINITE); CloseHandle(t2); }

    CloseHandle(pipe);
    closesocket(tcp_sock);
    logmsg("Connection closed");
    return 0;
}

/* ---------- Accept loop ---------- */
static int run_bridge(void)
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        logmsg("FATAL: WSAStartup failed");
        return 1;
    }

    g_listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_listen_sock == INVALID_SOCKET) {
        logmsg("FATAL: socket() failed: %d", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    int optval = 1;
    setsockopt(g_listen_sock, SOL_SOCKET, SO_REUSEADDR,
               (const char *)&optval, sizeof(optval));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((u_short)g_port);
    inet_pton(AF_INET, g_bind, &addr.sin_addr);

    if (bind(g_listen_sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        logmsg("FATAL: bind(%s:%d) failed: %d", g_bind, g_port, WSAGetLastError());
        closesocket(g_listen_sock);
        WSACleanup();
        return 1;
    }

    if (listen(g_listen_sock, SOMAXCONN) == SOCKET_ERROR) {
        logmsg("FATAL: listen() failed: %d", WSAGetLastError());
        closesocket(g_listen_sock);
        WSACleanup();
        return 1;
    }

    logmsg("Listening on %s:%d", g_bind, g_port);
    logmsg("Pipe target: %s", g_pipe);

    while (g_running) {
        struct sockaddr_in client_addr;
        int client_len = sizeof(client_addr);
        SOCKET client = accept(g_listen_sock,
                               (struct sockaddr *)&client_addr, &client_len);
        if (client == INVALID_SOCKET) {
            if (!g_running)
                break;
            logmsg("accept() error: %d", WSAGetLastError());
            continue;
        }

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
        logmsg("Accepted from %s:%d", ip, ntohs(client_addr.sin_port));

        HANDLE t = CreateThread(NULL, 0, handle_connection,
                                (LPVOID)(uintptr_t)client, 0, NULL);
        if (t)
            CloseHandle(t);   /* detach */
        else {
            logmsg("ERROR: CreateThread failed");
            closesocket(client);
        }
    }

    closesocket(g_listen_sock);
    g_listen_sock = INVALID_SOCKET;
    WSACleanup();
    return 0;
}

/* ---------- Console mode ---------- */
static BOOL WINAPI console_ctrl_handler(DWORD ctrl)
{
    if (ctrl == CTRL_C_EVENT || ctrl == CTRL_CLOSE_EVENT) {
        logmsg("Shutting down…");
        g_running = FALSE;
        if (g_listen_sock != INVALID_SOCKET)
            closesocket(g_listen_sock);
        return TRUE;
    }
    return FALSE;
}

static int run_console(void)
{
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
    logmsg("KeePassXC TCP Bridge — console mode");
    return run_bridge();
}

/* ---------- Windows Service ---------- */
static void report_svc_status(DWORD state, DWORD exit_code, DWORD wait_hint)
{
    static DWORD checkpoint = 1;
    g_svc_status.dwCurrentState  = state;
    g_svc_status.dwWin32ExitCode = exit_code;
    g_svc_status.dwWaitHint      = wait_hint;
    g_svc_status.dwControlsAccepted =
        (state == SERVICE_START_PENDING) ? 0 : SERVICE_ACCEPT_STOP;
    g_svc_status.dwCheckPoint =
        (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkpoint++;
    SetServiceStatus(g_svc_status_handle, &g_svc_status);
}

static void WINAPI svc_ctrl_handler(DWORD ctrl)
{
    if (ctrl == SERVICE_CONTROL_STOP) {
        report_svc_status(SERVICE_STOP_PENDING, NO_ERROR, 3000);
        g_running = FALSE;
        if (g_listen_sock != INVALID_SOCKET)
            closesocket(g_listen_sock);
    }
}

static void open_service_log(void)
{
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    /* Replace .exe with .log */
    char *dot = strrchr(path, '.');
    if (dot)
        strcpy(dot, ".log");
    else
        strcat(path, ".log");
    g_logfile = fopen(path, "a");
}

static void read_service_registry(void)
{
    HKEY key;
    char reg_path[512];
    _snprintf(reg_path, sizeof(reg_path),
              "SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", SERVICE_NAME);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, reg_path, 0,
                      KEY_READ, &key) != ERROR_SUCCESS)
        return;

    DWORD type, size;
    DWORD port_val;
    size = sizeof(port_val);
    if (RegQueryValueExA(key, "Port", NULL, &type,
                         (LPBYTE)&port_val, &size) == ERROR_SUCCESS
        && type == REG_DWORD) {
        g_port = (int)port_val;
    }

    size = sizeof(g_bind);
    RegQueryValueExA(key, "BindAddress", NULL, NULL, (LPBYTE)g_bind, &size);

    size = sizeof(g_pipe);
    RegQueryValueExA(key, "PipeName", NULL, NULL, (LPBYTE)g_pipe, &size);

    RegCloseKey(key);
}

static void WINAPI svc_main(DWORD argc, LPSTR *argv)
{
    (void)argc;
    (void)argv;

    g_svc_status_handle = RegisterServiceCtrlHandlerA(SERVICE_NAME,
                                                      svc_ctrl_handler);
    if (!g_svc_status_handle)
        return;

    g_svc_status.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    g_svc_status.dwServiceSpecificExitCode = 0;

    report_svc_status(SERVICE_START_PENDING, NO_ERROR, 3000);

    open_service_log();
    read_service_registry();

    logmsg("KeePassXC TCP Bridge — service mode");

    report_svc_status(SERVICE_RUNNING, NO_ERROR, 0);

    int rc = run_bridge();

    if (g_logfile) {
        fclose(g_logfile);
        g_logfile = NULL;
    }

    report_svc_status(SERVICE_STOPPED,
                      rc ? ERROR_SERVICE_SPECIFIC_ERROR : NO_ERROR, 0);
}

/* ---------- Service install / uninstall ---------- */
static int install_service(void)
{
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        logmsg("OpenSCManager failed — run as Administrator (error %lu)",
               GetLastError());
        return 1;
    }

    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);

    char cmd[MAX_PATH + 32];
    _snprintf(cmd, sizeof(cmd), "\"%s\" -service", exe_path);

    SC_HANDLE svc = CreateServiceA(
        scm,
        SERVICE_NAME,
        SERVICE_DISPLAY,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        cmd,
        NULL,   /* load order group */
        NULL,   /* tag ID */
        NULL,   /* dependencies */
        NULL,   /* account (LocalSystem) */
        NULL);  /* password */

    if (!svc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS)
            logmsg("Service already exists. Uninstall first or use 'sc config'.");
        else
            logmsg("CreateService failed: error %lu", err);
        CloseServiceHandle(scm);
        return 1;
    }

    /* Set description */
    SERVICE_DESCRIPTIONA desc;
    desc.lpDescription = (LPSTR)SERVICE_DESC_S;
    ChangeServiceConfig2A(svc, SERVICE_CONFIG_DESCRIPTION, &desc);

    /* Store parameters in registry */
    HKEY key;
    char reg_path[512];
    _snprintf(reg_path, sizeof(reg_path),
              "SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", SERVICE_NAME);

    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, reg_path, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL,
                        &key, NULL) == ERROR_SUCCESS) {
        DWORD port_val = (DWORD)g_port;
        RegSetValueExA(key, "Port", 0, REG_DWORD,
                       (LPBYTE)&port_val, sizeof(port_val));
        RegSetValueExA(key, "BindAddress", 0, REG_SZ,
                       (LPBYTE)g_bind, (DWORD)strlen(g_bind) + 1);
        RegSetValueExA(key, "PipeName", 0, REG_SZ,
                       (LPBYTE)g_pipe, (DWORD)strlen(g_pipe) + 1);
        RegCloseKey(key);
    }

    logmsg("Service \"%s\" installed", SERVICE_NAME);
    logmsg("  Executable: %s", cmd);
    logmsg("  Registry:   %s", reg_path);
    logmsg("  Port:       %d", g_port);
    logmsg("  Bind:       %s", g_bind);
    logmsg("  Pipe:       %s", g_pipe);
    logmsg("");
    logmsg("Start:  sc start %s", SERVICE_NAME);
    logmsg("Stop:   sc stop %s", SERVICE_NAME);
    logmsg("Status: sc query %s", SERVICE_NAME);
    logmsg("Log:    %s (next to the .exe)", "kpxc-bridge.log");

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

static int uninstall_service(void)
{
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        logmsg("OpenSCManager failed — run as Administrator (error %lu)",
               GetLastError());
        return 1;
    }

    SC_HANDLE svc = OpenServiceA(scm, SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (!svc) {
        logmsg("Service \"%s\" not found: error %lu", SERVICE_NAME, GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }

    /* Stop if running */
    SERVICE_STATUS status;
    if (ControlService(svc, SERVICE_CONTROL_STOP, &status))
        logmsg("Stopping service…");
    Sleep(1500);

    if (!DeleteService(svc)) {
        logmsg("DeleteService failed: error %lu", GetLastError());
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return 1;
    }

    logmsg("Service \"%s\" uninstalled", SERVICE_NAME);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

/* ---------- Usage ---------- */
static void usage(const char *prog)
{
    fprintf(stderr,
        "KeePassXC TCP Bridge\n"
        "Forwards TCP connections to the KeePassXC browser integration named pipe.\n\n"
        "Usage: %s [options] [command]\n\n"
        "Options:\n"
        "  -port PORT    TCP listen port        (default: %d)\n"
        "  -bind ADDR    TCP bind address        (default: %s)\n"
        "  -pipe NAME    Named pipe path         (default: %s)\n\n"
        "Commands:\n"
        "  install       Install as Windows service (options set registry defaults)\n"
        "  uninstall     Remove Windows service\n"
        "  (none)        Run in console mode\n\n"
        "Examples:\n"
        "  %s                                    Console, default settings\n"
        "  %s -port 9999 -bind 10.0.0.1          Console, custom port/bind\n"
        "  %s -port 19455 install                 Install service on port 19455\n"
        "  %s uninstall                           Remove service\n\n"
        "Note: install/uninstall require an elevated (Administrator) prompt.\n"
        "Service log is written to kpxc-bridge.log next to the executable.\n"
        "Ensure Windows Firewall allows inbound TCP on the configured port.\n",
        prog, DEFAULT_PORT, DEFAULT_BIND, DEFAULT_PIPE,
        prog, prog, prog, prog);
}

/* ---------- Main ---------- */
int main(int argc, char **argv)
{
    enum {
        MODE_CONSOLE,
        MODE_SERVICE,
        MODE_INSTALL,
        MODE_UNINSTALL,
        MODE_HELP
    } mode = MODE_CONSOLE;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-port") == 0 && i + 1 < argc) {
            g_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-bind") == 0 && i + 1 < argc) {
            strncpy(g_bind, argv[++i], sizeof(g_bind) - 1);
            g_bind[sizeof(g_bind) - 1] = '\0';
        } else if (strcmp(argv[i], "-pipe") == 0 && i + 1 < argc) {
            strncpy(g_pipe, argv[++i], sizeof(g_pipe) - 1);
            g_pipe[sizeof(g_pipe) - 1] = '\0';
        } else if (strcmp(argv[i], "-service") == 0) {
            mode = MODE_SERVICE;
        } else if (strcmp(argv[i], "install") == 0) {
            mode = MODE_INSTALL;
        } else if (strcmp(argv[i], "uninstall") == 0) {
            mode = MODE_UNINSTALL;
        } else if (strcmp(argv[i], "-h") == 0 ||
                   strcmp(argv[i], "--help") == 0 ||
                   strcmp(argv[i], "/?") == 0) {
            mode = MODE_HELP;
        } else {
            fprintf(stderr, "Unknown option: %s\n\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    switch (mode) {
    case MODE_CONSOLE:
        return run_console();

    case MODE_SERVICE: {
        SERVICE_TABLE_ENTRYA table[] = {
            { (LPSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONA)svc_main },
            { NULL, NULL }
        };
        if (!StartServiceCtrlDispatcherA(table)) {
            DWORD err = GetLastError();
            if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
                logmsg("Not running under the Service Control Manager.");
                logmsg("Use 'install' to register as a service, or run without flags for console mode.");
            } else {
                logmsg("StartServiceCtrlDispatcher failed: %lu", err);
            }
            return 1;
        }
        return 0;
    }

    case MODE_INSTALL:
        return install_service();

    case MODE_UNINSTALL:
        return uninstall_service();

    case MODE_HELP:
        usage(argv[0]);
        return 0;
    }

    return 0;
}
