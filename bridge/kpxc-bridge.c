/*
 * kpxc-bridge.c — TCP-to-named-pipe bridge for KeePassXC
 *
 * Forwards TCP connections to the KeePassXC browser integration named pipe,
 * allowing remote clients (e.g., an MCP server in a VM) to communicate with
 * KeePassXC running on this Windows host.
 *
 * Runs as a system tray application in the user's session — no service
 * account needed, automatic access to KeePassXC's per-user named pipe.
 *
 * Build (Visual Studio Developer Command Prompt):
 *   rc resources/kpxc-bridge.rc
 *   cl /O2 /W4 kpxc-bridge.c resources/kpxc-bridge.res /Fe:kpxc-bridge.exe /link /SUBSYSTEM:WINDOWS ws2_32.lib advapi32.lib shell32.lib user32.lib
 *
 * Build (MinGW / MSYS2):
 *   gcc -O2 -Wall -mwindows -o kpxc-bridge.exe kpxc-bridge.c resources/kpxc-bridge.rc -lws2_32 -ladvapi32 -lshell32 -luser32
 *
 * Build (Zig CC, cross-compile from any OS):
 *   zig cc -O2 -target x86_64-windows-gnu kpxc-bridge.c resources/kpxc-bridge.rc -lws2_32 -ladvapi32 -lshell32 -luser32 -Wl,--subsystem,windows -o kpxc-bridge.exe
 *
 * Usage:
 *   kpxc-bridge.exe                         Run as tray app (default)
 *   kpxc-bridge.exe -console                Run in console mode (Ctrl+C to stop)
 *   kpxc-bridge.exe -port 19455             Set TCP listen port
 *   kpxc-bridge.exe -bind 192.168.0.1       Bind to specific interface
 *   kpxc-bridge.exe -pipe \\.\pipe\NAME     Override named pipe path
 *   kpxc-bridge.exe install                 Add to user startup (login)
 *   kpxc-bridge.exe uninstall               Remove from user startup
 *
 * Requires: Windows Vista or later. No external dependencies.
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shellapi.h>
#include <stdio.h>
#include "resources/resource.h"
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")

/* ---------- Defaults ---------- */
#define DEFAULT_PORT    19455
#define DEFAULT_BIND    "0.0.0.0"
#define DEFAULT_PIPE    "\\\\.\\pipe\\org.keepassxc.KeePassXC.BrowserServer"
#define PIPE_PREFIX     "org.keepassxc.KeePassXC.BrowserServer"
#define APP_NAME        "KeePassXC TCP Bridge"
#define STARTUP_KEY     "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define STARTUP_VALUE   "KeePassXCBridge"
#define BUFFER_SIZE     65536

/* Tray icon messages */
#define WM_TRAYICON     (WM_USER + 1)
#define WM_UPDATE_TIP   (WM_USER + 2)
#define IDM_STATUS      1001
#define IDM_EXIT        1002

/* ---------- Globals ---------- */
static int           g_port = DEFAULT_PORT;
static char          g_bind[64] = DEFAULT_BIND;
static char          g_pipe[256] = DEFAULT_PIPE;
static SOCKET        g_listen_sock = INVALID_SOCKET;
static volatile BOOL g_running = TRUE;
static FILE         *g_logfile = NULL;
static volatile LONG g_connections = 0;

/* Tray globals */
static HWND            g_hwnd = NULL;
static NOTIFYICONDATAA g_nid = {0};
static HICON           g_icon_idle = NULL;
static HICON           g_icon_active = NULL;

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

    /* Fallback: enumerate pipes matching the KeePassXC prefix */
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA("\\\\.\\pipe\\*", &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (strncmp(fd.cFileName, PIPE_PREFIX, strlen(PIPE_PREFIX)) == 0) {
                _snprintf(suffixed, sizeof(suffixed),
                          "\\\\.\\pipe\\%s", fd.cFileName);
                FindClose(hFind);
                logmsg("Found pipe by enumeration: %s", suffixed);
                return suffixed;
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
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

    InterlockedIncrement(&g_connections);
    if (g_hwnd) PostMessageA(g_hwnd, WM_UPDATE_TIP, 0, 0);

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

    InterlockedDecrement(&g_connections);
    if (g_hwnd) PostMessageA(g_hwnd, WM_UPDATE_TIP, 0, 0);

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
        logmsg("Shutting down...");
        g_running = FALSE;
        if (g_listen_sock != INVALID_SOCKET)
            closesocket(g_listen_sock);
        return TRUE;
    }
    return FALSE;
}

static int run_console(void)
{
    /* GUI subsystem: allocate a console for -console mode */
    if (!AttachConsole(ATTACH_PARENT_PROCESS))
        AllocConsole();
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
    freopen("CONIN$", "r", stdin);
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
    logmsg("%s - console mode", APP_NAME);
    return run_bridge();
}

/* ---------- System tray ---------- */

static void tray_update_tooltip(void)
{
    LONG n = InterlockedCompareExchange(&g_connections, 0, 0);
    HICON want = (n > 0) ? g_icon_active : g_icon_idle;
    if (g_nid.hIcon != want) {
        g_nid.hIcon = want;
    }
    if (n > 0)
        _snprintf(g_nid.szTip, sizeof(g_nid.szTip),
                  "%s - %ld active", APP_NAME, n);
    else
        _snprintf(g_nid.szTip, sizeof(g_nid.szTip),
                  "%s - :%d", APP_NAME, g_port);
    Shell_NotifyIconA(NIM_MODIFY, &g_nid);
}

static void tray_create(HWND hwnd)
{
    g_nid.cbSize           = sizeof(g_nid);
    g_nid.hWnd             = hwnd;
    g_nid.uID              = 1;
    g_nid.uFlags           = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    HINSTANCE hInst = GetModuleHandle(NULL);
    g_icon_idle   = LoadIconA(hInst, MAKEINTRESOURCEA(IDI_TRAY_DISCONNECTED));
    g_icon_active = LoadIconA(hInst, MAKEINTRESOURCEA(IDI_TRAY_CONNECTED));
    if (!g_icon_idle)
        g_icon_idle = LoadIconA(NULL, (LPCSTR)IDI_APPLICATION);
    if (!g_icon_active)
        g_icon_active = g_icon_idle;
    g_nid.hIcon            = g_icon_idle;
    _snprintf(g_nid.szTip, sizeof(g_nid.szTip),
              "%s - :%d", APP_NAME, g_port);
    Shell_NotifyIconA(NIM_ADD, &g_nid);
}

static void tray_destroy(void)
{
    Shell_NotifyIconA(NIM_DELETE, &g_nid);
}

static void show_context_menu(HWND hwnd)
{
    POINT pt;
    GetCursorPos(&pt);

    HMENU menu = CreatePopupMenu();

    LONG n = InterlockedCompareExchange(&g_connections, 0, 0);
    char status[128];
    _snprintf(status, sizeof(status),
              "Listening on %s:%d (%ld conn)", g_bind, g_port, n);
    AppendMenuA(menu, MF_STRING | MF_GRAYED, IDM_STATUS, status);
    AppendMenuA(menu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(menu, MF_STRING, IDM_EXIT, "Exit");

    SetForegroundWindow(hwnd);
    TrackPopupMenu(menu, TPM_RIGHTALIGN | TPM_BOTTOMALIGN,
                   pt.x, pt.y, 0, hwnd, NULL);
    DestroyMenu(menu);
}

static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg,
                                 WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_TRAYICON:
        if (lParam == WM_RBUTTONUP || lParam == WM_LBUTTONUP)
            show_context_menu(hwnd);
        return 0;

    case WM_UPDATE_TIP:
        tray_update_tooltip();
        return 0;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDM_EXIT) {
            g_running = FALSE;
            if (g_listen_sock != INVALID_SOCKET)
                closesocket(g_listen_sock);
            tray_destroy();
            PostQuitMessage(0);
        }
        return 0;

    case WM_CLOSE:
    case WM_ENDSESSION:
        g_running = FALSE;
        if (g_listen_sock != INVALID_SOCKET)
            closesocket(g_listen_sock);
        tray_destroy();
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProcA(hwnd, msg, wParam, lParam);
    }
}

static DWORD WINAPI bridge_thread(LPVOID param)
{
    (void)param;
    return (DWORD)run_bridge();
}

static void open_log_file(void)
{
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char *dot = strrchr(path, '.');
    if (dot)
        strcpy(dot, ".log");
    else
        strcat(path, ".log");
    g_logfile = fopen(path, "a");
}

static int run_tray(void)
{
    /* Prevent multiple instances */
    HANDLE hMutex = CreateMutexA(NULL, TRUE, "Global\\KeePassXCBridge_SingleInstance");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBoxA(NULL, "KeePassXC TCP Bridge is already running.",
                     APP_NAME, MB_OK | MB_ICONINFORMATION);
        if (hMutex) CloseHandle(hMutex);
        return 0;
    }

    /* Open log file next to the exe */
    open_log_file();
    logmsg("%s - tray mode", APP_NAME);

    /* Register window class */
    WNDCLASSEXA wc = {0};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = wnd_proc;
    wc.hInstance      = GetModuleHandle(NULL);
    wc.lpszClassName  = "KPXCBridgeTray";
    RegisterClassExA(&wc);

    /* Create message-only window */
    g_hwnd = CreateWindowExA(
        0, "KPXCBridgeTray", APP_NAME, 0,
        0, 0, 0, 0,
        HWND_MESSAGE, NULL, GetModuleHandle(NULL), NULL);

    /* Create tray icon */
    tray_create(g_hwnd);

    /* Start bridge on background thread */
    HANDLE hThread = CreateThread(NULL, 0, bridge_thread, NULL, 0, NULL);

    /* Message pump */
    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    /* Cleanup */
    g_running = FALSE;
    if (g_listen_sock != INVALID_SOCKET)
        closesocket(g_listen_sock);
    if (hThread) {
        WaitForSingleObject(hThread, 3000);
        CloseHandle(hThread);
    }

    if (g_logfile) {
        fclose(g_logfile);
        g_logfile = NULL;
    }

    return 0;
}

/* ---------- Startup registry (HKCU\...\Run) ---------- */

static int install_startup(void)
{
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);

    char cmd[MAX_PATH + 64];
    _snprintf(cmd, sizeof(cmd), "\"%s\"", exe_path);
    if (g_port != DEFAULT_PORT) {
        char buf[32];
        _snprintf(buf, sizeof(buf), " -port %d", g_port);
        strcat(cmd, buf);
    }

    HKEY key;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, STARTUP_KEY, 0,
                      KEY_WRITE, &key) != ERROR_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to open startup registry key\n");
        return 1;
    }
    RegSetValueExA(key, STARTUP_VALUE, 0, REG_SZ,
                   (LPBYTE)cmd, (DWORD)strlen(cmd) + 1);
    RegCloseKey(key);

    printf("Added to startup: %s\n", cmd);
    printf("The bridge will start automatically when you log in.\n");
    return 0;
}

static int uninstall_startup(void)
{
    HKEY key;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, STARTUP_KEY, 0,
                      KEY_WRITE, &key) != ERROR_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to open startup registry key\n");
        return 1;
    }
    LONG result = RegDeleteValueA(key, STARTUP_VALUE);
    RegCloseKey(key);

    if (result == ERROR_SUCCESS)
        printf("Removed from startup.\n");
    else
        printf("Not found in startup registry.\n");
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
        "  -port PORT    TCP listen port         (default: %d)\n"
        "  -bind ADDR    TCP bind address         (default: %s)\n"
        "  -pipe NAME    Named pipe path          (default: %s)\n"
        "  -console      Run in console mode      (default: tray app)\n\n"
        "Commands:\n"
        "  install       Add to user startup (runs on login)\n"
        "  uninstall     Remove from user startup\n"
        "  (none)        Run as system tray app\n\n"
        "Examples:\n"
        "  %s                                     Tray app, default settings\n"
        "  %s -console                            Console mode (Ctrl+C to stop)\n"
        "  %s -port 19455 install                  Add to startup on port 19455\n"
        "  %s uninstall                            Remove from startup\n\n"
        "Log is written to kpxc-bridge.log next to the executable.\n"
        "Ensure Windows Firewall allows inbound TCP on the configured port.\n",
        prog, DEFAULT_PORT, DEFAULT_BIND, DEFAULT_PIPE,
        prog, prog, prog, prog);
}

/* ---------- Main ---------- */
int main(int argc, char **argv)
{
    enum {
        MODE_TRAY,
        MODE_CONSOLE,
        MODE_INSTALL,
        MODE_UNINSTALL,
        MODE_HELP
    } mode = MODE_TRAY;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-port") == 0 && i + 1 < argc) {
            g_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-bind") == 0 && i + 1 < argc) {
            strncpy(g_bind, argv[++i], sizeof(g_bind) - 1);
            g_bind[sizeof(g_bind) - 1] = '\0';
        } else if (strcmp(argv[i], "-pipe") == 0 && i + 1 < argc) {
            strncpy(g_pipe, argv[++i], sizeof(g_pipe) - 1);
            g_pipe[sizeof(g_pipe) - 1] = '\0';
        } else if (strcmp(argv[i], "-console") == 0) {
            mode = MODE_CONSOLE;
        } else if (strcmp(argv[i], "-service") == 0) {
            mode = MODE_TRAY;  /* backward compat: treat as tray */
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
    case MODE_TRAY:      return run_tray();
    case MODE_CONSOLE:   return run_console();
    case MODE_INSTALL:   return install_startup();
    case MODE_UNINSTALL: return uninstall_startup();
    case MODE_HELP:      usage(argv[0]); return 0;
    }

    return 0;
}
