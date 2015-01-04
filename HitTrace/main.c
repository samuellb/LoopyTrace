/*

  Copyright (c) 2014-2015 Samuel Lidén Borell <samuel@kodafritt.se>
 
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
  
  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.
  
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.

*/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <TlHelp32.h>

#include "resource.h"
#include "x86ops.h"


#define HIT_PATCHED 0x1 /* Patched initially (but maybe unpatched later) */
#define HIT_REACHED 0x2 /* Reached (and unpatched) */
#define HIT_IGNORED 0x4 /* Ignored by user */
typedef struct SectionInfo {
    struct SectionInfo* next;
    
    DWORD va_start;
    DWORD va_size;
    
    BYTE *orig; /* copy of original code section contents */
    BYTE *hits; /* patched and/or reached */
} SectionInfo;

typedef enum {
               /* Granularity */
    TRC_CALL,  /*  Functions       Inject a function and overwrite all function prologues with a CALL */
    TRC_INT3,  /*  Instructions    Inject an exception handler and replace all instructions with INT3 */
    TRC_LOOP,  /*  Functions       Overwrite all function prologues with a JMP -2, and wait for the program to reach there */
    TRC_NX     /*  Pages           Inject an exception handler and mark all pages as non-executable. */
                /* (only LOOP tracing is implemented) */
} TraceMode;

/* NT internal stuff */
#define ProcessBasicInformation 0
typedef struct {
    PVOID Reserved1;
    /*PPEB*/PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
typedef DWORD (*PNtQueryInformationProcess)(HANDLE, DWORD, PVOID, ULONG, PULONG);

static HINSTANCE ntdll;
static PNtQueryInformationProcess pNtQueryInformationProcess;
static HANDLE heap;

static HANDLE tracedProc;
static DWORD tracedProcId;
static TraceMode traceMode;
static SectionInfo *sections;
static IMAGE_DOS_HEADER mz_header;
static IMAGE_NT_HEADERS pe_header;
static BYTE hits_thumbnail[1025];
static BOOL hasTraceData;
static BOOL has_rdata;
static DWORD last_activity;
static int draw_num;
#define ACTIVITY_FLASH_MS 100

static BOOL CALLBACK DialogProc(HWND, UINT, WPARAM, LPARAM);
static void ShowLastErrorDialog(HWND hwnd, char *format);
static void ShowErrorDialog(HWND hwnd, char *format, DWORD errorCode);
static BOOL toggle_attached_state(HWND hwnd, BOOL is_attached);
static BOOL attach(HWND hwnd);
static void detach();
static void save_dump(HWND hwnd, char *filename);
static BOOL patch_code(HWND hwnd, DWORD va_start, DWORD va_size);
static DWORD next_function_start(BYTE *code, DWORD p, DWORD va_size);
static void unpatch_loops(HWND hwnd);
static void free_sections(HWND hwnd);
static DWORD find_process(char *name);

int WINAPI WinMain(HINSTANCE hInstance,
                   HINSTANCE hPrevInstance,
                   LPSTR cmdLine,
                   int windowState)

{
    HWND hwnd;
    MSG msg;
    HICON icon;
    int status;
    
    heap = GetProcessHeap();
    InitCommonControls();
/*{
BYTE data[] = { 0x66, 0x39, 0x0f, 0x0f };
ShowErrorDialog(NULL, "len = %1!d!", get_x86_instr_size(data, 0, sizeof(data)));
ExitProcess(0);
}*/
    
    hwnd = CreateDialog(hInstance, MAKEINTRESOURCE(ID_MAINDLG), 0, DialogProc);
    if (!hwnd) {
        ShowLastErrorDialog(0, "Error 0x%1!04x! occurred when trying to create dialog box.");
        return 1;
    }
    
    icon = LoadIcon(hInstance, "A");
    SendMessage(hwnd, WM_SETICON, ICON_BIG, (WPARAM)icon);
    ShowWindow(hwnd, windowState);
    while ((status = GetMessage(&msg, NULL, 0, 0)) != 0) {
        if (status == -1) {
            detach();
            return -1;
        }
        
        if (!IsDialogMessage(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    
    detach();
    return msg.wParam;
}

static BOOL CALLBACK DialogProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message) {
    case WM_INITDIALOG:
        EnableWindow(GetDlgItem(hwnd, ID_DETACH), FALSE);
        EnableWindow(GetDlgItem(hwnd, ID_SAVE), FALSE);
        /*CheckDlgButton(hwnd, ID_TRCCALL, BST_CHECKED);*/ /* Not implemented yet */
        SetDlgItemText(hwnd, ID_PROCENTRY, "notepad.exe");
        return TRUE;
    case WM_COMMAND:
        switch (wParam) {
        case ID_ATTACH: {
            /* Parse process id/name entry */
            DWORD pid;
            char buff[1024];
            BOOL is_integer, ok;
            
            buff[0] = '\0';
            GetDlgItemText(hwnd, ID_PROCENTRY, buff, sizeof(buff));
            if (!buff[0]) {
                MessageBox(hwnd, "Please enter a process name or ID.", NULL, MB_ICONERROR);
                return TRUE;
            }
            
            pid = GetDlgItemInt(hwnd, ID_PROCENTRY, &is_integer, FALSE);
            if (!is_integer) {
                /* Assume that it's a process name */
                pid = find_process(buff);
                if (!pid) {
                    MessageBox(hwnd, "Process not found (searched by name).", NULL, MB_ICONERROR);
                    return TRUE; 
                }
                if (pid == (DWORD)-1) {
                    MessageBox(hwnd, "Multiple processes exist with this name. Please specify a PID.", NULL, MB_ICONEXCLAMATION);
                    return TRUE; 
                }
            }
            
            /*if (IsDlgButtonChecked(hwnd, ID_TRCCALL) == BST_CHECKED) {
                traceMode = TRC_CALL;
            } else if (IsDlgButtonChecked(hwnd, ID_TRCINT3) == BST_CHECKED) {
                traceMode = TRC_INT3;
            } else if (IsDlgButtonChecked(hwnd, ID_TRCLOOP) == BST_CHECKED) {
                traceMode = TRC_LOOP;
            }*/
            traceMode = TRC_LOOP;
            
            /* Open process */
            detach();
            tracedProcId = pid;
            tracedProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
            if (!tracedProc) {
                if (is_integer && GetLastError() == ERROR_INVALID_PARAMETER) {
                    MessageBox(hwnd, "Process not found (searched by ID).", NULL, MB_ICONERROR);
                } else {
                    ShowLastErrorDialog(hwnd, "Error 0x%1!04x! occurred when trying to open process.");
                }
                return TRUE;
            }
            free_sections(hwnd); /* clean up from previous runs */
            
            ok = attach(hwnd);
            if (ok) {
                ZeroMemory(hits_thumbnail, sizeof(hits_thumbnail));
            }
            hasTraceData = ok;
            toggle_attached_state(hwnd, ok);
            EnableWindow(GetDlgItem(hwnd, ID_SAVE), ok);
            return TRUE; }
        case ID_DETACH:
            detach();
            toggle_attached_state(hwnd, FALSE);
            return TRUE;
        case ID_MENUBTN: {
            RECT rect;
            HMENU menu;
            TPMPARAMS tpm;
            int state;
            
            /* Determine screen location of the button */
            GetWindowRect((HWND)lParam, &rect);
            
            /* Load menu and disable/enable items */
            menu = LoadMenu(GetModuleHandle(NULL), MAKEINTRESOURCE(ID_HITSMENU));
            menu = GetSubMenu(menu, 0);
            /*state = (tracedProc ? 0 : MF_GRAYED);
            EnableMenuItem(menu, ID_ADDHITSCODE, state);
            EnableMenuItem(menu, ID_ADDHITSRANGE, state);
            EnableMenuItem(menu, ID_CLEARHITS, state);*/
            EnableMenuItem(menu, ID_CLEARHITS, hasTraceData ? 0 : MF_GRAYED);
            
            /* Show popup menu */
            tpm.cbSize = sizeof(tpm);
            tpm.rcExclude = rect;
            int cmd = TrackPopupMenuEx(menu, TPM_LEFTALIGN | TPM_LEFTBUTTON | TPM_VERTICAL | TPM_RETURNCMD,
                                       rect.left, rect.bottom, hwnd, &tpm);
            DestroyMenu(menu);
            return TRUE;
        }
        case ID_SAVE: {
            OPENFILENAME ofn = { 0 };
            char path[MAX_PATH];
            path[0] = '\0';
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hwnd;
            ofn.hInstance = GetModuleHandle(NULL);
            ofn.lpstrFilter = "LoopyTrace masked PE dump files (*.loopy.exe)\0*.loopy.exe\0All files (*.*)\0*.*\0\0";
            ofn.lpstrFile = path;
            ofn.nMaxFile = MAX_PATH-1;
            ofn.lpstrTitle = "Save masked PE dump";
            ofn.Flags = OFN_NOREADONLYRETURN | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
            ofn.lpstrDefExt = "loopy.exe";
            if (GetSaveFileName(&ofn)) {
                save_dump(hwnd, ofn.lpstrFile);
            }
            return TRUE; }
        case IDCANCEL:
        case ID_EXIT:
            PostQuitMessage(0);
            return TRUE;
        }
        return TRUE;
    case WM_CTLCOLORSTATIC:
        if ((HWND)lParam == GetDlgItem(hwnd, ID_COPYRIGHT)) {
            SetBkMode((HDC)wParam, TRANSPARENT);
            SetTextColor((HDC)wParam, GetSysColor(COLOR_GRAYTEXT));
            return (BOOL)CreateSolidBrush(GetSysColor(COLOR_3DFACE));
        }
        return FALSE;
    case WM_DRAWITEM: {
        DRAWITEMSTRUCT *dis = (PDRAWITEMSTRUCT)lParam;
        switch (dis->CtlID) {
        case ID_HITS: {
            int i;
            int saved = SaveDC(dis->hDC);
            DWORD now = GetTickCount();
            COLORREF bgColor;
            COLORREF hitColor;
            if (!tracedProc) {
                bgColor = 0xCCCCCC;
                hitColor = 0x996666;
            } else if (last_activity < now-ACTIVITY_FLASH_MS) {
                bgColor = 0xDDBBBB;
                hitColor = 0xCC3333;
            } else if ((++draw_num & 1) == 0) {
                bgColor = 0xBBBBDD;
                hitColor = 0x3333CC;
            } else {
                bgColor = 0xCCCCEE;
                hitColor = 0x3A3ADD;
            }
            HBRUSH bgBrush = CreateSolidBrush(bgColor);
            HBRUSH hitBrush = CreateSolidBrush(hitColor);
            
            FillRect(dis->hDC, &dis->rcItem, bgBrush);
            if (hasTraceData) {
                BOOL was_on = FALSE;
                RECT on_rect;
                on_rect.left = 0;
                on_rect.top = 0;
                on_rect.bottom = dis->rcItem.bottom;
                for (i = 0; i < 1024; i++) {
                    BOOL on = hits_thumbnail[i] & HIT_REACHED;
                    if (on && !was_on) {
                        on_rect.left = i*dis->rcItem.right / 1024;
                        was_on = TRUE;
                    } else if (!on && was_on) {
                        on_rect.right = i*dis->rcItem.right / 1024;
                        FillRect(dis->hDC, &on_rect, hitBrush);
                        was_on = FALSE;
                    }
                }
                
                if (was_on) {
                    on_rect.right = dis->rcItem.right;
                    FillRect(dis->hDC, &on_rect, hitBrush);
                }
            }
            
            RestoreDC(dis->hDC, saved);
            DeleteObject(bgBrush);
            DeleteObject(hitBrush);
            return TRUE; }
        }
        return FALSE; }
    case WM_TIMER:
        switch (wParam) {
        case ID_PATCHTIMER:
            unpatch_loops(hwnd);
            break;
        case ID_UITIMER:
            InvalidateRect(GetDlgItem(hwnd, ID_HITS), NULL, FALSE);
            break;
        }
        return TRUE;
    case WM_DESTROY:
        PostQuitMessage(0);
        return TRUE;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return TRUE;
    }
    return FALSE;
}

static BOOL toggle_attached_state(HWND hwnd, BOOL is_attached)
{
    if (is_attached) {
        EnableWindow(GetDlgItem(hwnd, ID_ATTACH), FALSE);
        EnableWindow(GetDlgItem(hwnd, ID_DETACH), TRUE);
        SetTimer(hwnd, ID_PATCHTIMER, 1, NULL); /* FIXME maybe it shouldn't be a timer? */
        SetTimer(hwnd, ID_UITIMER, 100, NULL);
    } else {
        EnableWindow(GetDlgItem(hwnd, ID_ATTACH), TRUE);
        EnableWindow(GetDlgItem(hwnd, ID_DETACH), FALSE);
        KillTimer(hwnd, ID_PATCHTIMER);
        KillTimer(hwnd, ID_UITIMER);
        InvalidateRect(GetDlgItem(hwnd, ID_HITS), NULL, FALSE);
    }
}

static DWORD find_process(char *name)
{
    PROCESSENTRY32 entry;
    DWORD foundPid = 0;
    entry.dwSize = sizeof(entry);
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &entry)) {
        do {
            if (CompareString(LOCALE_USER_DEFAULT, NORM_IGNORECASE | SORT_STRINGSORT, name, -1, entry.szExeFile, -1) == CSTR_EQUAL) {
                if (foundPid) {
                    foundPid = (DWORD)-1; /* Multiple processes with this name */
                    break;
                }
                foundPid = entry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return foundPid;
}

static BOOL enable_debug_privs(HWND hwnd)
{
    HANDLE token = 0;
    TOKEN_PRIVILEGES privs = { 0 };
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) {
        if (hwnd) {
            MessageBox(0, "Tried to adjust own debug privileges, but OpenProcessToken failed.", NULL, MB_ICONERROR);
        }
        return FALSE;
    }
    
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &privs.Privileges[0].Luid)) {
        if (hwnd) {
            MessageBox(0, "Tried to adjust own debug privileges, but LookupPrivilegeValue failed.", NULL, MB_ICONERROR);
        }
        return FALSE;
    }
    
    privs.PrivilegeCount = 1;
    privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(token, FALSE, &privs, 0, NULL, 0)) {
        if (hwnd) {
            MessageBox(0, "Tried to adjust own debug privileges, but AdjustTokenPrivilege failed.", NULL, MB_ICONERROR);
        }
        return FALSE;
    }
    
    return TRUE;
}

/* hwnd is a handle of the main window */
/* TODO for programs that destroy their headers (if that's possible?) we
   should also implement reading of the EXE file, and/or simply trying to find
   all executable pages by brute force (could use VirtualQueryEx) */
static BOOL attach(HWND hwnd)
{
    DWORD res;
    PROCESS_BASIC_INFORMATION pbi;
    DWORD imagebase = 0;
    DWORD pe_start;
    DWORD sections_start;
    IMAGE_SECTION_HEADER *sectiontable;
    int num_sections, i;
    
    /* Look up NtQueryInformationProcess function */
    if (!ntdll) {
        ntdll = LoadLibrary("ntdll");
        if (!ntdll && hwnd) {
            MessageBox(hwnd, "Failed to load NTDLL library.", NULL, MB_ICONERROR);
        }
    }
    
    if (ntdll && !pNtQueryInformationProcess) {
        pNtQueryInformationProcess = (PNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
        if (!pNtQueryInformationProcess && hwnd) {
            MessageBox(hwnd, "Missing function NtQueryInformationProcess in NTDLL library.", NULL, MB_ICONERROR);
        }
    }
    
    /* Get image base */
    if (pNtQueryInformationProcess) {
        if (enable_debug_privs(hwnd)) {
            res = pNtQueryInformationProcess(tracedProc, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
            if (res != 0) {
                if (hwnd) {
                    ShowErrorDialog(hwnd, "NtQueryInformationProcess failed with error 0x%1!04x!", res);
                }
            } else if (!ReadProcessMemory(tracedProc, (char*)pbi.PebBaseAddress + 8, &imagebase, sizeof(imagebase), NULL) && hwnd) {
                MessageBox(hwnd, "Failed to read image base.", NULL, MB_ICONERROR);
            }
        }
    }
    
    if (!imagebase) {
        if (hwnd) {
            /* TODO ask for image base instead. Usually it's either 0x00400000 or 0x01000000 */
            /* TODO or could try a brute force scan in this case */
            imagebase = 0x00400000;
        } else {
            imagebase = 0x00400000; /* might work */
        }
        if (!imagebase) {
            return FALSE;
        }
    }
    
    /* Get MZ header */
    if (!ReadProcessMemory(tracedProc, (PCVOID)imagebase, &mz_header, sizeof(mz_header), NULL)) {
        if (hwnd) {
            MessageBox(hwnd, "Failed to read EXE/MZ header at image base.", NULL, MB_ICONERROR);
        }
        return FALSE;
    }
    
    if (mz_header.e_magic != 0x5A4D && mz_header.e_magic != 0x4D5A) { /* MZ or ZM */
        if (hwnd) {
            MessageBox(hwnd, "Data at image base is not an MZ header.", NULL, MB_ICONERROR);
        }
        return FALSE;
    }
    
    /* Get PE header */
    pe_start = imagebase + mz_header.e_lfanew;
    if (!ReadProcessMemory(tracedProc, (PCVOID)pe_start, &pe_header, sizeof(pe_header), NULL)) {
        if (hwnd) {
            MessageBox(hwnd, "Failed to read memory of PE header.", NULL, MB_ICONERROR);
        }
        return FALSE;
    }
    
    if (pe_header.Signature != 0x4550) {
        if (hwnd) {
            MessageBox(hwnd, "Data referenced by MZ e_lfanew offset is not an PE header.", NULL, MB_ICONERROR);
        }
        return FALSE;
    }
    
    /* Get section table */
    sections_start = pe_start +
                     sizeof(pe_header.Signature) +
                     sizeof(pe_header.FileHeader) +
                     pe_header.FileHeader.SizeOfOptionalHeader;
    num_sections = pe_header.FileHeader.NumberOfSections;
    sectiontable = HeapAlloc(heap, 0, num_sections*sizeof(IMAGE_SECTION_HEADER));
    if (!sectiontable) {
        if (hwnd) {
            MessageBox(hwnd, "Failed to allocate memory for section table.", NULL, MB_ICONERROR);
        }
        return FALSE;
    }
    
    if (!ReadProcessMemory(tracedProc, (PCVOID)sections_start, sectiontable, num_sections*sizeof(IMAGE_SECTION_HEADER), NULL)) {
        if (hwnd) {
            MessageBox(hwnd, "Failed to read memory of section header.", NULL, MB_ICONERROR);
        }
        return FALSE;
    }
    
    /* Determine if we have an rdata section */
    has_rdata = FALSE;
    for (i = 0; i < num_sections; i++) {
        if ((sectiontable[i].Characteristics & (IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_EXECUTE)) != IMAGE_SCN_CNT_INITIALIZED_DATA)
            continue;
        
        if (CompareString(LOCALE_USER_DEFAULT, NORM_IGNORECASE|NORM_IGNORESYMBOLS|SORT_STRINGSORT, sectiontable[i].Name, -1, ".rdata", -1) != CSTR_EQUAL &&
            CompareString(LOCALE_USER_DEFAULT, NORM_IGNORECASE|NORM_IGNORESYMBOLS|SORT_STRINGSORT, sectiontable[i].Name, -1, ".rodata", -1) != CSTR_EQUAL)
            continue;
        
        has_rdata = TRUE;
        MessageBox(0, "HAS rdata", "", 64);
    }
    
    /* Patch code sections */
    for (i = 0; i < num_sections; i++) {
        DWORD va_start, va_size;
        
        if ((sectiontable[i].Characteristics & (IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_EXECUTE)) == 0) {
            continue;
        }
        
        va_start = imagebase + sectiontable[i].VirtualAddress;
        va_size = sectiontable[i].Misc.VirtualSize;
        
        //ShowErrorDialog(hwnd, "Found code section starting at %1!08x!", va_start);
        patch_code(hwnd, va_start, va_size);
        
break; /* Don't patch bidvm sections */
    }
    
    HeapFree(heap, 0, sectiontable);
    last_activity = 0;
    draw_num = 0;
    return TRUE;
}

static BOOL patch_code(HWND hwnd, DWORD va_start, DWORD va_size)
{
    BYTE *orig;
    SectionInfo *section;
    
    /* Add to linked list */
    section = HeapAlloc(heap, 0, sizeof(SectionInfo));
    section->va_start = va_start;
    section->va_size = va_size;
    section->orig = NULL;
    section->hits = HeapAlloc(heap, HEAP_ZERO_MEMORY, va_size);
    section->next = sections;
    sections = section;
    
    /* Read existing code */
    orig = HeapAlloc(heap, 0, va_size);
    if (!orig) {
        if (hwnd) {
            MessageBox(hwnd, "Failed to allocate memory for code section.", NULL, MB_ICONERROR);
        }
        return FALSE;
    }
    section->orig = orig;
    
    if (!ReadProcessMemory(tracedProc, (PCVOID)va_start, orig, va_size, NULL)) {
        if (hwnd) {
            MessageBox(hwnd, "Failed to read memory of code section.", NULL, MB_ICONERROR);
        }
        return FALSE;
    }
    
    /* Run a pass over the code and scan for data references, and mark the
    referenced data as non-code (if it's in the code section). */
    // TODO
    // TODO what to do with indexed access, e.g. call [PTRTABLE+i] ?
    
    /* Patch code */
    switch (traceMode) {
    case TRC_CALL:
        /* TODO */
        break;
    case TRC_INT3:
        /* TODO */
        break;
    case TRC_LOOP: {
        /* If the EXE doesn't have any .rdata section, assume it was smaller
           than a page (4K) and has been merged with the code section(s) */
        DWORD p = (has_rdata ? 0 : 0x1000);
        while (p < va_size) {
            /* JMP -2 with prefixes to allow instructions up to 15 bytes (the maximum) to be replaced */
          //static const BYTE infinite_loop[15] = { 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x67, 0x2E, 0xEB, 0xFE };
            static const BYTE infinite_loop[2] = { 0xEB, 0xFE };
            
            
            /* Skip one-byte instructions */
            /*
            BYTE instrsize;
            int skipped = 0;
            for (;;) {
                if (p >= va_size) goto patch_loop_end;
                if (skipped++ > 5) goto patch_loop_end;
                instrsize = get_x86_instr_size(orig, p, va_size);
                if (instrsize >= 2) break;
                p += instrsize;
            }*/
            
            /* Patch function */
            if ((section->hits[p] & HIT_IGNORED) == 0) {
                //if (!WriteProcessMemory(tracedProc, (LPVOID)(va_start + p), (LPCVOID)&infinite_loop[15-instrsize], instrsize, NULL)) {
                if (!WriteProcessMemory(tracedProc, (LPVOID)(va_start + p), (LPCVOID)infinite_loop, 2, NULL)) {
                    MessageBox(hwnd, "Failed to patch memory in code section.", NULL, MB_ICONERROR);
                    break;
                }
                section->hits[p] |= HIT_PATCHED;
            }
            p += 2/*instrsize*/;
            
            p = next_function_start(orig, p, va_size);
        }
      patch_loop_end:
        break; }
    case TRC_NX:
        /* TODO */
        break;
    }
    return TRUE;
}

static DWORD next_function_start(BYTE *code, DWORD p, DWORD va_size)
{
    int gapsize;
    do {
        /* Search for return opcode */
        for (;;) {
            BYTE c, opsize;
            
            if (p >= va_size) goto end;
            c = code[p];
            
            if (c == 0xC3) break; /* ret (we ignore retf since it's not used in Win32 programs) */
            if (c == 0xC2) { p += 2; break; } /* ret WORD */
            
            opsize = get_x86_instr_size(code, p, va_size);
            if (opsize == 255 && p < va_size && (code[p] != 0 || p < va_size-15)) {
                /*ShowErrorDialog(0, "Invalid opcode at 0x%1!08x! (relative to section start)", p);*/
                opsize = 1;
            }
            p += opsize;
        }
        p++;
        
        /* Skip NOP and INT3 gap between functions */
        gapsize = 0;
        for (;;) {
            if (p >= va_size) goto end;
            if (code[p] != 0x90 && code[p] != 0xCC) break;
            gapsize++;
            p++;
        }
        
        /* Check that's it's actually valid code */
        {
            BYTE opsize = get_x86_instr_size(code, p, va_size);
            if (opsize == 255 && p < va_size-20) continue;
            if (code[p+2] < 0x10 && code[p+3] == 0x01) {
                /* Check for jump table with a single entry */
                if ((code[p+4] == 0x90 || code[p+4] == 0xCC) &&
                    (code[p+5] == 0x90 || code[p+5] == 0xCC)) {
                    continue;
                }
            }
            if (code[p+2] == code[p+6] && code[p+6] == code[p+10] &&
                code[p+3] == code[p+7] && code[p+7] == code[p+11] &&
                opsize != 4) {
                /* Probably a jump table */
                continue;
            }
            if (code[p+2] == code[p+10] && code[p+2] == code[p+18] &&
                code[p+3] == code[p+11] && code[p+3] == code[p+19] &&
                opsize != 4 && opsize != 8) {
                /* Probably a jump table with data imbetween */
                continue;
            }
        }
        
        // TODO should ignore if the instr is single-byte and we aren't sure it's a function
        /*if (gapsize == 0 && get_x86_instr_size(code, p, va_size) == 1) {
            continue;
        }*/
        
        /* If we are at an even 8-byte boundary OR we saw at least one NOP/INT3
           then we assume it's a start of a function */
    } while ((p & 0x7) != 0 && gapsize == 0);
  end:
    return p;
}

static void unpatch_loops(HWND hwnd)
{
    THREADENTRY32 entry;
    BOOL foundProcess = FALSE;
    BOOL activity = FALSE;
    entry.dwSize = sizeof(entry);
    
    /* Enumerate all threads of the traced process */
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (Thread32First(snapshot, &entry)) {
        do {
            CONTEXT ctx;
            HANDLE hthread;
            BOOL ok;
            DWORD eip, func_end, p;
            SectionInfo *section;
            BYTE data[2];
            BYTE instrsize;
            
            /* Thread of a traced process? */
            if (entry.th32OwnerProcessID != tracedProcId) {
                continue;
            }
            foundProcess = TRUE;
            
            /* Get EIP */
            ZeroMemory(&ctx, sizeof(ctx));
            ctx.ContextFlags = CONTEXT_CONTROL;
            hthread = OpenThread(THREAD_GET_CONTEXT, FALSE, entry.th32ThreadID);
            ok = GetThreadContext(hthread, &ctx);
            CloseHandle(hthread);
            if (!ok) {
                continue;
            }
            eip = ctx.Eip;
            
            /* Check if it was patched and is not reached/unpatched */
            for (section = sections; section; section = section->next) {
                if (eip >= section->va_start && eip < section->va_start + section->va_size) {
                    break;
                }
            }
            if (!section || section->hits[eip-section->va_start] != HIT_PATCHED) {
                continue;
            }
            
            /* Read memory at EIP */
            p = eip-section->va_start;
            if (ReadProcessMemory(tracedProc, (PCVOID)eip, data, 2, NULL)) {
                if (data[0] != 0xEB || data[1] != 0xFE) {
                //if (data[0] != 0xEB && data[0] != 0x26) {
                    /* Patch code has been overwritten */
                    continue;
                }
            }
            
            /* Restore original memory */
            /*instrsize = get_x86_instr_size(section->orig, p, section->va_size);
            if (instrsize == 255) instrsize = 15;*/
            WriteProcessMemory(tracedProc, (LPVOID)eip, &sections->orig[p], 2, NULL);
            
            func_end = next_function_start(section->orig, eip-section->va_start, section->va_size);
            for (; p < func_end; p++) {
                section->hits[p] |= HIT_REACHED;
                hits_thumbnail[p*1024/section->va_size] |= HIT_REACHED;
            }
            
            activity = TRUE;
        } while (Thread32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    
    if (activity) {
        last_activity = GetTickCount();
    } else {
        draw_num = 0;
    }
    
    if (!foundProcess) {
        CloseHandle(tracedProc);
        tracedProc = 0;
        tracedProcId = 0;
        toggle_attached_state(hwnd, FALSE);
    }
}

static void detach(HWND hwnd)
{
    if (tracedProc) {
        /* Restore process memory */
        SectionInfo *section, *tmp;
        BOOL failed = FALSE;
        for (section = sections; section; section = section->next) {
            if (!WriteProcessMemory(tracedProc, (LPVOID)section->va_start, section->orig, section->va_size, NULL)) {
                failed = TRUE;
            }
        }
        
        if (failed && hwnd) {
            MessageBox(hwnd, "Failed to restore memory of code section.", NULL, MB_ICONERROR);
        }
        
        CloseHandle(tracedProc);
    }
    tracedProc = 0;
    tracedProcId = 0;
}

static void free_sections(HWND hwnd)
{
    SectionInfo *section, *next;
    for (section = sections; section; section = next) {
        next = section->next;
        HeapFree(heap, 0, section);
    }
    sections = NULL;
}

#define ROUNDPG(n) (((n)+0xFFF) & ~0xFFF)
static void save_dump(HWND hwnd, char *filename)
{
    DWORD num_code, size_code, num_other, size_init, size_uninit;
    DWORD byteswritten;
    IMAGE_DOS_HEADER doshdr;
    IMAGE_NT_HEADERS nthdr;
    IMAGE_SECTION_HEADER sectiontable[1];
    SectionInfo *section;
    HANDLE file = CreateFile(filename, GENERIC_WRITE, FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        if (hwnd) {
           ShowLastErrorDialog(hwnd, "Failed to save file! Error: 0x%1!04x!");
        }
        return;
    }
    
    /* Determine number of sections */
    num_code = 0;
    size_code = 0;
    num_other = 0;
    size_init = 0;
    size_uninit = 0;
    for (section = sections; section; section = section->next) {
        num_code++;
        size_code += section->va_size;
    }
    /* TODO copy non-code sections from the process as-is */
    /* TODO fill ignored code sections with 0x90 */
    
    /* Write header */
    ZeroMemory(&doshdr, sizeof(doshdr));
    doshdr.e_magic = IMAGE_DOS_SIGNATURE;
    doshdr.e_cblp = 0x90;
    doshdr.e_cp = 3;
    doshdr.e_cparhdr = 4;
    doshdr.e_maxalloc = 0xFFFF;
    doshdr.e_sp = 0xB8;
    doshdr.e_lfarlc = 0;
    doshdr.e_lfanew = /*0x20*/ sizeof(doshdr);
    WriteFile(file, &doshdr, sizeof(doshdr), &byteswritten, NULL);
    ZeroMemory(&nthdr, sizeof(nthdr));
    nthdr.Signature = IMAGE_NT_SIGNATURE;
    nthdr.FileHeader.Machine = 0x14C; /* i386 */
    nthdr.FileHeader.NumberOfSections = num_code + num_other;
    nthdr.FileHeader.TimeDateStamp = 0;
    nthdr.FileHeader.SizeOfOptionalHeader = 0xE0;
    nthdr.FileHeader.Characteristics = 0x103; /* executable, stripped relocs, 32-bit */
    nthdr.OptionalHeader.Magic = 0x10B; /* PE32 */
    nthdr.OptionalHeader.MajorLinkerVersion = 8;
    nthdr.OptionalHeader.SizeOfCode = ROUNDPG(size_code);
    nthdr.OptionalHeader.SizeOfInitializedData = ROUNDPG(size_init);
    nthdr.OptionalHeader.SizeOfUninitializedData = ROUNDPG(size_uninit);
    nthdr.OptionalHeader.AddressOfEntryPoint = 0x1000; /* FIXME */
    nthdr.OptionalHeader.BaseOfCode = sections->va_start & 0xFFFF;
    nthdr.OptionalHeader.BaseOfData = 0x50000; /* TODO */
    nthdr.OptionalHeader.ImageBase = sections->va_start & ~0xFFFF;
    nthdr.OptionalHeader.SectionAlignment = 0x1000;
    nthdr.OptionalHeader.FileAlignment = 0x1000;
    nthdr.OptionalHeader.MajorOperatingSystemVersion = 4;
    nthdr.OptionalHeader.MajorSubsystemVersion = 4;
    nthdr.OptionalHeader.SizeOfImage = 0x1000+ROUNDPG(size_code)+ROUNDPG(size_init);
    nthdr.OptionalHeader.SizeOfHeaders = 0x1000;
    nthdr.OptionalHeader.CheckSum = 0; /* TODO */
    nthdr.OptionalHeader.Subsystem = 2; /* Windows GUI */
    nthdr.OptionalHeader.SizeOfStackReserve = 0x100000;
    nthdr.OptionalHeader.SizeOfStackCommit = 0x1000;
    nthdr.OptionalHeader.SizeOfHeapReserve = 0x100000;
    nthdr.OptionalHeader.SizeOfHeapCommit = 0x1000;
    nthdr.OptionalHeader.NumberOfRvaAndSizes = 0x10;
    WriteFile(file, &nthdr, sizeof(nthdr), &byteswritten, NULL);
    
    /* Write section table */
    ZeroMemory(&sectiontable, sizeof(sectiontable));
    lstrcpy(sectiontable[0].Name, ".text");
    sectiontable[0].Misc.VirtualSize = sections->va_size;
    sectiontable[0].VirtualAddress = sections->va_start & 0xFFFF;
    sectiontable[0].SizeOfRawData = ROUNDPG(sections->va_size);
    sectiontable[0].PointerToRawData = 0x1000;
    sectiontable[0].Characteristics = IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_EXECUTE;
    WriteFile(file, sectiontable, sizeof(sectiontable), &byteswritten, NULL);
    
    /* Write section contents */
    /* TODO write all code sections */
    SetFilePointer(file, 0x1000, NULL, FILE_BEGIN);
    {
    int i, len = sections->va_size;
    BYTE *data = HeapAlloc(heap, 0, len);
    FillMemory(data, len, 0x90); /* Fill with NOP */
    for (i = 0; i < len; i++) {
        if ((sections->hits[i] & HIT_REACHED) != 0) {
            /* Only reached code is included */
            data[i] = sections->orig[i];
        }
    }
    WriteFile(file, data, len, &byteswritten, NULL);
    HeapFree(heap, 0, data);
    }
    /* TODO for others: simply output as-is */
    
    /* Padding */
    SetFilePointer(file, 0x1000+ROUNDPG(size_code)+ROUNDPG(size_init), NULL, FILE_BEGIN);
    SetEndOfFile(file);
    
    CloseHandle(file);
}

static void ShowLastErrorDialog(HWND hwnd, char *format)
{
    ShowErrorDialog(hwnd, format, GetLastError());
}

static void ShowErrorDialog(HWND hwnd, char *format, DWORD errorCode)
{
    char buff[1024];
    DWORD_PTR fmtargs[1] = { (DWORD_PTR)errorCode };
    buff[0] = 'A';
    FormatMessage(FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ARGUMENT_ARRAY, format, 0, 0, buff, sizeof(buff), (va_list*)fmtargs);
    MessageBox(hwnd, buff, NULL, MB_ICONERROR | MB_OK);
}

// BUGS:
//   - nothing is traced in winmine.exe - why? doesn't seem to have any NOP gaps
//    - Call FlushInstructionCache(hprocess, startaddr, size)
//

// POSSIBLE NEW FEATURES:
//   - log parameters in calls. Try to detect parameter types (e.g. address -> log data)
//

// POSSIBLE NEW TRACING METHODS:
//   - scan the stack for return addresses instead? (from this we can also check the call instr before and determine the called address)
//     completely passive. need to filter out non-return-code data on the stack (can check that there's a call instr).
//     could also scan for current EIP.
//   - somehow probe the I-cache?
//
