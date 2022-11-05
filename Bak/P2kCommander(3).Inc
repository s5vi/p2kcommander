include windows.inc
include user32.inc
include kernel32.inc
include shell32.inc
include comctl32.inc
include comdlg32.inc
include setupapi.inc
include advapi32.inc
include gdi32.inc
include imagehlp.inc
include masm32.inc
;include .\image.inc 
include ole32.inc
include oleaut32.inc
include wininet.inc
include shlwapi.inc
include ws2_32.inc
include .\anigif.inc

includelib user32.lib
includelib kernel32.lib
includelib shell32.lib
includelib comctl32.lib
includelib comdlg32.lib
includelib setupapi.lib
includelib advapi32.lib
includelib gdi32.lib
includelib imagehlp.lib
includelib masm32.lib
;includelib .\image.lib
includelib ole32.lib 
includelib oleaut32.lib
includelib wininet.lib
includelib shlwapi.lib 
includelib ws2_32.lib
includelib .\anigif.lib

;include \RadAsm\masm\inc\radbg.inc  ;debug

      literal MACRO quoted_text:VARARG
        LOCAL local_text
        .data
          local_text db quoted_text,0
        align 4
        .code
        EXITM <local_text>
      ENDM
      StrAddr MACRO quoted_text:VARARG
        EXITM <ADDR literal(quoted_text)>
      ENDM
      return MACRO arg
        mov eax, arg
        ret
      ENDM
WinMain				PROTO :DWORD,:DWORD,:DWORD,:DWORD
WndProc				PROTO :DWORD,:DWORD,:DWORD,:DWORD
FillFileInfo1		PROTO :DWORD
FillFileInfo2		PROTO :DWORD
InsertColumn		PROTO
UpdatelParam1		PROTO
UpdatelParam2		PROTO
ShowCurrentFocus1	PROTO :DWORD
ShowCurrentFocus2	PROTO :DWORD
CompareFunc1		PROTO :DWORD,:DWORD,:DWORD
CompareFunc2		PROTO :DWORD,:DWORD,:DWORD
SetCurrDir1			PROTO :DWORD,:DWORD
SetCurrDir2			PROTO :DWORD,:DWORD
P2kGetFileList1		PROTO :DWORD
P2kGetFileList2		PROTO :DWORD
SelectFirst1		PROTO :DWORD
SelectFirst2		PROTO :DWORD
EnumChild 			PROTO :DWORD,:DWORD
InitHyperLinkClass	PROTO
GetDrives1			PROTO
GetDrives2			PROTO
Cmd_RDELEM			PROTO
LEUnicode_cvt		PROTO
SetStatusText		PROTO :DWORD,:DWORD,:DWORD
FSAC_search_file	PROTO
;FileCount				PROTO	:DWORD
GetLocalFilename	PROTO :DWORD,:DWORD
UpdateStatusBar		PROTO
SmartRefreshCopy	PROTO :DWORD,:DWORD,:DWORD
SmartRefreshDel		PROTO :DWORD
SmartRefreshDelDir	PROTO :DWORD
SmartRefreshAttr	PROTO	:DWORD
UploadFile1			PROTO	:DWORD
UploadFile2			PROTO	:DWORD
WriteLogFile			PROTO
LoadConfig				PROTO	:HWND
SaveConfig				PROTO	:HWND
LoadPos					PROTO	:HWND
SetP2kRecordSize		PROTO
GetP2kSize					PROTO
GetAttrib				PROTO
SetSize					PROTO
SetAttrib				PROTO
SetAttrib2				PROTO
SaveLog					PROTO	:HWND
P2kGetFileListHW		PROTO
P2kUploadHW				PROTO	
P2kDownloadHW			PROTO	

WaitProc				PROTO	:HWND,:DWORD,:WPARAM,:LPARAM
GetMsgAddr				PROTO	:DWORD
SetP2kCB1				PROTO	:HWND
SetP2kCB2				PROTO	:HWND
ActualizeCB				PROTO
LBProc					PROTO	:DWORD,:DWORD,:DWORD,:DWORD
LVProc					PROTO	:DWORD,:DWORD,:DWORD,:DWORD
P2kCopy_down			PROTO	:DWORD,:DWORD,:DWORD,:DWORD
P2kCopy_up				PROTO	:DWORD,:DWORD,:DWORD,:DWORD
P2kSeem_down			PROTO	:DWORD,:DWORD,:DWORD,:DWORD
P2kSeem_up				PROTO	:DWORD,:DWORD,:DWORD,:DWORD
CheckP2k05				PROTO
P2kGetSeemList1			PROTO	:DWORD
P2kGetSeemList2			PROTO	:DWORD
CopyMemory				PROTO	:DWORD,:DWORD,:DWORD
ReadFunctionSeems		PROTO	:DWORD,:DWORD
GetSeemBit				PROTO	:DWORD,:DWORD,:DWORD,:DWORD
FindP2kSeem				PROTO
Save1Seem				PROTO
P2k_AT					PROTO
FindUSBLAN				PROTO
HexAnswer				PROTO	:DWORD,:DWORD
File_CountOld			PROTO	
ezxname					PROTO
UpdateDropdown			PROTO
logstat					PROTO	:DWORD


IDD_DIALOG			equ 1000

IDM_MENU			equ 10000
IDM_FILE_EXIT		equ 10001
IDM_HELP_ABOUT		equ 10101

IDB_BITMAPS 	    equ  301
IDC_BTN1			equ 1007 ;view F3
IDC_BTN23			equ 1026 ;edit F4
IDC_BTN2			equ 1004 ;move F6
IDC_BTN3			equ 1008 ;attrib F2
IDC_BTN4			equ 1009 ;mkdir F7
IDC_BTN24			equ 1027 ;copy F5
IDC_BTN6			equ 1011 ;del F8
IDC_BTN7			equ 1012 ;reread left
IDC_BTN8			equ 1013 ;reread right
IDC_BTN9			equ 1022 ;reread keyb accel
IDC_BTN11			equ 1017 ;exit F10
IDC_BTN12			equ 1018 ;altF1
IDC_BTN13			equ 1019 ;altF2
IDC_BTN14			equ 1020 ;TAB
IDC_BTN16			equ 1104 ;esc
IDC_BTN19			equ 1021 ;insert (select)
IDC_BTN5			equ 1010 ;restart F9
IDC_BTN21			equ 1025 ;
IDC_BTN28			equ 1028 ;

IDC_CBO1			equ 1005
IDC_CBO2			equ 1006

IDR_ACCEL			equ 2000

testfilenum equ 90

BCM_FIRST        	equ 01600h
BCM_SETIMAGELIST    equ BCM_FIRST + 0002h

HLM_SETTYPE				equ		WM_USER+200 ; lParam = HLINK_URL/HLINK_EMAIL wndxtra 0
HLM_SETHOTCOLOR			equ		WM_USER+201 ; lParam = Hot color wndxtra 4
HLM_SETTEXTCOLOR		equ		WM_USER+202 ; lParam = Normal text color wndxtra 8
HLM_SETSUBJECT			equ		WM_USER+203 ; lParam = Email subject line wndxtra 24
HLM_SETBODY				equ		WM_USER+204 ; lParam = Email body wndxtra 28
HLM_SETUNDERLINE		equ		WM_USER+205 ; lParam = Underline link TRUE/FALSE wndxtra 32

HLM_ISHOT				equ		WM_USER+206 ; Sent to parent wParam = ID, lParam = hControl

HLINK_URL				equ		0
HLINK_EMAIL				equ		1

MUTEX_ALL_ACCESS equ 1F0001h

SERVER_PORT         equ 11000
TEMP_BUFFER_SIZE    equ 128
REQ_WINSOCK_VER     equ 2


MOVmw    MACRO Var1, Var2
               lea     esi, Var2
               lea     edx, Var1
            REPEAT     2
                  mov     al, [esi]
                  mov     [edx], al
                  inc     esi
                  inc     edx
            ENDM
         ENDM


.const

ClassName			db 'DLGCLASS',0
AppName				db 'P2kCommander',0
;AboutMsg			db 'MASM32 RadASM Dialog as main',13,10,'Copyright © MASM32 2001',0
;szStarted			db "P2kCommander launched.",0 ;39
;szFilenamesLoaded	db " filenames loaded in ",0 ;40
;szSeconds			db " milliseconds.",0 ;41

PUBLIC hInstance

.data?

hBackgr				dd ?
hBackgr2			dd ?
hBrushD				dd ?
hBrushDwm			dd ?

hAccel 				dd ?

hInstance			dd ?
CommandLine			dd ?
hWnd				dd ?
hImageTestS			dd ?
hImageListS			dd ?
hImageListC			dd ?
hBitmap				dd ?
hIcon				dd ?
hIconPhone			dd ?
hReread2			dd ?
hLB1				dd ?
hLB2				dd ?
hF2					dd ?
hF3					dd ?
hF4					dd ?
hF5					dd ?
hF6					dd ?
hF7					dd ?
hF8					dd ?
hF9					dd ?
hWrite				dd ?
hBar				dd ?
hLog				dd ?
hReadFile			dd ?
hSaveFile			dd ?
nBytes				dd ?
writtenb			dd ?
hMemFile			dd ?
HoldT            	dd ?
hURL				dd ?
hURL2				dd ?
hURL3				dd ?
hURL4				dd ?
hAbout				dd ?
Lft 				FILETIME <?>
time				SYSTEMTIME <?>
;SHEXEC				SHELLEXECUTEINFO <?>
CurrentItem			dd ?
hHead1				dd ?
hHead2				dd ?
hList1 				dd ?
hList2  			dd ?
hListSeem  			dd ?
hFontL	            dd ?
hFontL2	            dd ?
hFontL3	            dd ?
hFontlog			dd ?
LeftRight		dd ?  ; 0:left 1:right
LeftRightS		dd ?  ; LeftRight at start of operation
PrevPos1		dd ?  ; save listview pos when change dir
PrevPos11		dd ?  ; save listview pos when change dir
PrevPos2		dd ?
hMenu			dd ?
hRMenu			dd ?
hSMenu			dd ?
hSPMenu			dd ?
hWaitCursor		dd ?

Wrect				RECT <?>
ListPlacement1		WINDOWPLACEMENT <?>
ListPlacement2		WINDOWPLACEMENT <?>
DirPlacement1		WINDOWPLACEMENT <?>
DirPlacement2		WINDOWPLACEMENT <?>
LBPlacement2		WINDOWPLACEMENT <?>
RereadPlacement2	WINDOWPLACEMENT <?>
F2Placement			WINDOWPLACEMENT <?>
F3Placement			WINDOWPLACEMENT <?>
F4Placement			WINDOWPLACEMENT <?>
F5Placement			WINDOWPLACEMENT <?>
F6Placement			WINDOWPLACEMENT <?>
F7Placement			WINDOWPLACEMENT <?>
F8Placement			WINDOWPLACEMENT <?>
F9Placement			WINDOWPLACEMENT <?>
BarPlacement		WINDOWPLACEMENT <?>
LogPlacement		WINDOWPLACEMENT <?>
StatPlacement		WINDOWPLACEMENT <?>
MainPlacement		WINDOWPLACEMENT <?>
SplitbarPlacement	WINDOWPLACEMENT <?>
ListWp1				LVBKIMAGE <?>
ListWp2				LVBKIMAGE <?>
hEdit1				dd ?
hStatus				dd ?
P2kIconIndex		dd ?
P2kQIconIndex		dd ?
P2kDIconIndex		dd ?
hdi					HD_ITEM <?>
hLVHeader1			dd ?
hLVHeader2			dd ?
hLVHImagelist		dd ?

BUTTON_IMAGELIST STRUC
				himl HIMAGELIST ? 
				margin RECT <>
				uAlign DWORD ?
BUTTON_IMAGELIST ENDS
 
PBUTTON_IMAGELIST TYPEDEF      PTR BUTTON_IMAGELIST ; Pointer to structure type

ButtImList1		BUTTON_IMAGELIST <?>
ButtImList2		BUTTON_IMAGELIST <?>
ButtImList3		BUTTON_IMAGELIST <?>
ButtImList4		BUTTON_IMAGELIST <?>
ButtImList5		BUTTON_IMAGELIST <?>
ButtImList6		BUTTON_IMAGELIST <?>
ButtImList7		BUTTON_IMAGELIST <?>
ButtImList8		BUTTON_IMAGELIST <?>
ButtImList9		BUTTON_IMAGELIST <?>
hImagelist1			dd ?
hImagelist2			dd ?
hImagelist3			dd ?
hImagelist4			dd ?
hImagelist5			dd ?
hImagelist6			dd ?
hImagelist7			dd ?
hImagelist8			dd ?
hImagelist9			dd ?

hwndTool			dd ?
phone_model			db 30 dup (?)
StartTicks			dd ?

DrawBuffer			db 255 dup(?)
;TransTimer			dd ?
;TimerID				dd ?
;ScanTimerID			dd ?

SaveTxColor			dd ?
SaveBkColor			dd ?
hSystemImageList	dd ?
LayeredSave			dd ?
LayeredOrig			dd ?
hSplitBar			dd ?
hBrushSPB			dd ?
SplitterX			dd ?
SplitterY			dd ?
OldList1WndProc		dd ?
OldList2WndProc		dd ?
OSVer				OSVERSIONINFO <?>

hKey1				dd ?
hKeyS1				dd ?
hKey2				dd ?
hKey3				dd ?
hKey4				dd ?
hRetVal				dd ?

hMemConfigPtrs		dd ?
WPlacement		WINDOWPLACEMENT <?>
hMutex				dd ?
hSMutex				dd ?

;--------------- language
hMemLang			dd ? ; pointer to message texts
nLangCount			dd ? ; number of msgs
hMemLangPtrs		dd ? ; pointer to msg pointer array
;--------------- end of language
hMemList			dd ? ; pointer to message texts
nFileCount			dd ? ; number of msgs
hMemFilePtrs		dd ? ; pointer to msg pointer array
;--------------- hidden files
hMemHiddenF			dd ? ; pointer to message texts
nHiddenFCount		dd ? ; number of msgs
hMemHiddenFPtrs		dd ? ; pointer to msg pointer array

;--------------- seem
hMemSeem			dd ? ; pointer to message texts
nSeemCount			dd ? ; number of msgs
hMemSeemPtrs		dd ? ; pointer to msg pointer array
hMemSeemF			dd ? ; pointer to message texts
nSeemFCount			dd ? ; number of msgs
hMemSeemFPtrs		dd ? ; pointer to msg pointer array
hMemF				dd ? ; pointer to message texts
nFCount				dd ? ; number of msgs
hMemFPtrs			dd ? ; pointer to msg pointer array
;--------------- end of seem
isSeemRoot			dd ?

processInfo		PROCESS_INFORMATION <>

SplashTimerID	dd ?
UpdateTimerID	dd ?
hSplash			dd ?

.data

;/* From Iczelions tutorial #27:What we need for a tooltip */
ToolTipsClassName 	db "Tooltips_class32",0
;/* End of What we need for a tooltip */
hMemPtrs		dd 0

DATETIME   struct
        dyr       BYTE      4 dup(" ")
                  BYTE      '.'
        dmo       BYTE      2 dup(" ")
                  BYTE      '.'
        dda       BYTE      2 dup(" ")
                  BYTE      ' '
        dhour     BYTE      2 dup(" ")
                  BYTE      ':'
        dmin      BYTE      2 dup(" ")
                  BYTE      0
DATETIME   ends
cdt          DATETIME    <>
TimeFormat db " hh:mm",0

Keytabevent dd 0

;Heading1 db "Filename",0 ;43
;Heading2 db "Size",0 ;44
;Heading3 db "Ownr/Attr",0 ;45
;Heading4 db "Date/Time",0 ;46
FileNamePattern db "*.*",0
template db "%lu",0
FileNameSortOrder dd 0
SizeSortOrder dd 0

;szUpLR	db "Uploading Left to Right:",0 ;47
;szUpRL	db "Uploading Right to Left:",0 ;48
;szDnLR	db "Downloading Left to Right:",0 ;49
;szDnRL	db "Downloading Right to Left:",0 ;50
;szP2kLR	db "p2k to p2k Left to Right:",0 ;51
;szP2kRL db "p2k to p2k Right to Left:",0 ;52

szRootPath      db "C:\",0
szDot			db ".",0
bufferx			db 2710h dup (0) ;512 dup (0)
buffery			db 512 dup (0)
bufferz			db 512 dup (0)
bufferh			db 512 dup (0)
LaunchDir		db 512 dup (0)
Templates		db "\Templates\",0
Tempdir			db "\Temp\",0
szParentdir 	db "..",0
szDirMark		db "< DIR >",0
;EmptyDirMark	db "s5vi.vxxxstuff.com",0
;EmptyDirMarks5vi db "5",0

DrivePattern 	db "[*.*",0
;P2kPattern		db "P2k Mobile phone",0;"[-P2k-]",0  ;53

DestDir			db 255 dup (0)
P2kDirectory1	db 255 dup (0)
P2kDirectory2	db 255 dup (0)
P2kDirInit		db"/",0
P2kFilesize     dd 0
P2kFilesize2     dd 0
P2kFileattrib   dd 0
P2kFileattribOU dd 0
; config file
P2kLimit		dd -1
isFade			dd 0
is3g			dd 3	;0=standard, 1=safe 3g, 3=fast 3g
WinPos			dd 0,624,0,446
isSlashA		dd 1
isSlashB		dd 0
isSlashC		dd 0
isSlashE		dd 0
isNoob			dd 1
isUpdate		dd 1
isP2kAutostart	dd 0
isFileFilter	dd 0
FileFilter		db "/a"
FileFilter2		db "/*.*",0
				db 255 dup (0)
Drive1			dd 2
Drive2			dd 2
isManualCOM		dd 0
ManualCOM		db 20 dup (0)
szDrive1		db 255 dup (0)
szDrive2		db 255 dup (0)
ManualP2k05		dd 0
isVerboseLog	dd 0
isIIndexManual	dd 0
InterfaceIndex	 dd 8
isTargetOverride dd 0
isOverrideSlot4  dd 0
ManualSlot4		db 20 dup (0)
Fav1			db 255 dup (0)
isUSBLAN		dd 0
cmdUSBLAN		db 'at+mode=13',0
				db 244 dup (0)
actIP			db 255 dup (0)
isFixIP			dd 0				
; end of config file
isUSBLANold		dd 0
P2kLimit2		dd -1
isDir			dd 0
isUpDir			dd 0
Fulldir1		db 255 dup (0)
Fulldir2		db 255 dup (0)
szBackslash		db "\",0
szSlash			db "/",0
P2kLoadFiles	dd 0
Row2			dd 0
Row3			dd 0

;FontMS            db        'MS Sans Serif',0
;FontMS2           db       'Tahoma',0
;FontMSfixed       db       'Fixedsys',0

lf           LOGFONT     <>

P2kReady		dd 0
P2kRestart		dd 0
szP2kDev		db "P2k:",0
UnknownIcon		dd 3
Attrib 			dd 0
Attrib2			dd 0

;szDel			db "Are You sure to delete ?  -  ",0  ;54
;szDelConfirm	db "Delete confirmation",0  ;55
;szOvr			db "Are You overwrite file ?  -  ",0  ;56
;szOvrConfirm	db "Overwrite confirmation",0  ;57
szNotepad		db "notepad.exe",0  
szLister		db "lister.exe",0   

;TTbufferReread1 db "Alt-R: Re-read the files from actual drive to the left panel.",0 ;58
;TTbufferReread2 db "Alt-R: Re-read the files from actual drive to the right panel.",0 ;59
;TTbufferView	db "F3: View the actual file with Lister or Notepad.",0 ;60
;TTbufferEdit	db "F4: Edit the actual file with Notepad.",0 ;61
;TTbufferAttrib	db "F2: Change attributes of actual file",0 ;62
;TTbufferCopy	db "F5: Copy the actual file to the directory on opposite panel.",0 ;63 
;TTbufferMove	db "F6: Copy and delete the source",0 ;64
;TTbufferNew		db "F7: Make new directory, even if on P2K drive!!!",0 ;65
;TTbufferDel		db "F8/del: Deletes the actual file, or P2K directory with files in it!!",0 ;66
;TTbufferRest	db "F9: Restart phone.",0 ;67
;TTbufferSel1	db "Alt-F1: Select drive letter for the left panel.",0 ;68
;TTbufferSel2	db "Alt-F2: Select drive letter for the right panel.",0 ;69
;TTbufferLog 	db "Log window, informations on events.",0 ;70
;TTbufferPath 	db "Shows the actual path.",0 ;71
;TTbufferProg 	db "Completion bar for getting filelist.",0 ;72


;szRemovable		db " Removable disk",0 ;73
;szCdrom			db " CD-ROM",0 ;74
;szRamdisk		db " Ramdisk",0 ;75
;szRemote		db " Network drive",0 ;76
separator		db " ",0

isHide			dd 0

dwParts         dd 90,180,270,-1 ; statusbar darabok pozicioja
;dwParts         dd 84,154,206,-1 ; statusbar darabok pozicioja
;szType			db "Model:",0 ;77
;szName			db "Vols: ",0 ;78
;szFiles			db "Files:",0 ;79
;szFree			db "Space:",0 ;80
szKb			db " Kb",0

FreeOffset		dd 0
;szUnlimited		db "Unlimited",0 ;81

szP2kC			db "P2kCommander.exe",0

isDrag			dd 0

;LogFile			db "Received_filelist.raw",0

Key1			db ".p2kc",0
Key2			db "P2kCommander\DefaultIcon",0
Key3			db "P2kCommander\shell\open\command",0
Key4			db "SOFTWARE\Microsoft\Windows\CurrentVersion\Run",0
;Key5Val			db "SOFTWARE\Microsoft\Windows\CurrentVersion\Run\P2kAutostart",0
Key1Val			db "P2kCommander",0
KeyS1			db ".s4m",0
Key2Val			db ",0",0
Key3Val			db ' "%1"',0
Key4Val			db 'P2kAutostart',0
RClass			db "REG_SZ",0
Sep				db "----------------------",0
ConfigName		db ".config",0
LogName			db ".log",0
isBatch 		dd 0

;szN00b1			db "Selected partition is: ",0			;82
;szN00b2			db 10,13,"This can be modified in options dialog.",0 ;83			
;szN00bTitle		db "n00b reminder...",0			;84
;szWarningLimit	db 'Warning setting "number of files" is NOT unlimited !!!',13,10 ;85
;				db 'You will not see the whole filelist !!!',13,10 ;86
;				db 'You can change this setting in options menu.',13,10 ;87
;				db 'After that you must perform a "Re-read".',0 ;88
;szWarning		db "P2kCommander warning message:",0 ;89

P2kRecordSize		dd 10ch
P2kSizeOffset		dd 108h
P2kAttribOffset		dd 104h

szSlashA		db "/a",0
szSlashB		db "/b",0
szSlashC		db "/c",0
szSlashE		db "/e",0
szSlashG		db "/g",0

SlashPartition	db "/"
Partition		db "a",0,0,0,0
szSkinPath		db "/a/mobile/skins/",0
szEndBatch		db "Batch process complete! P2kCommander will exit now.",10,13
				db "Enjoy your new skin! Or whatever you've uploaded! Regards: s5vi.....",10,13
				db "Do you want powercycle your phone?",0
szNotConn		db "Phone not connected!",10,13
				db "You must plug phone,",10,13,"BEFORE you start *.p2kc file.",0				
szS4M			db 512 dup (0)
szS4MKey		db "skinner4moto\shell\open\command",0
hKey			dd 0
sizeS4M			dw 5

szWarnS4m		db "To open this skinpack you need skinner4moto!",10,13,"Get it from Knapster's website:",10,13
				db "http://skinner4moto.de.vu",10,13,"Or you have to rename this *.s4m to *.zip.",10,13
				db "Then unzip that standard zipfile, and click *.p2kc file",0 

iHwn			dd 0
fDown			dd 0
P2kcURL			db "http://www.el-co.hu/dl/LatestBeta",0
P2kcURL2		db "http://www.el-co.hu/dl/MessageBeta",0
P2kcURL3		db "http://www.el-co.hu/dl/Message.html",0
Ver				dd 0  ; actual version "V322"					
szOpen			db "open",0
;szExplore		db "explore",0
szExplorer		db "explorer",0
;szPath			db "http://s5vi.vxxxstuff.com/commander",0				
szP2kAutostart	db "\P2kAutostart.exe",0						 
KillP2kA		db "KillP2kA",0
SuspendP2kA		db "SuspendP2kA",0

P2kInstance1	db "P2kCommanderInstance",0
P2kInstance2	db "UpP2kCommander",0

W2Kesi			dd 0
isThreadComplete dd 0
ProcessedFiles	dd 0
AttribHW		dd 0
NameHW			dd 0

_Row DWORD 0
_lvi LV_ITEM <>
_lvc LV_COLUMN <>
_sfi SHFILEINFO <>
_buffer BYTE 255 dup (0)

FileAll			db "/*.*",0				
sizeP2kc		dw 5
szKey			db "P2kCommander\shell\open\command",0
crlfsep			db "-------------",0
;cdummy 			db "/c/dummyfile",0
Thread_ID		dd 0
fromThread		dd 1
fromThread2		dd 1
ofn   OPENFILENAME <>
FilterString 	db "Motorola Seem Files",0,"*.seem",0
             	db "All Files",0,"*.*",0,0
FilterString2 	db "USB data payload files",0,"*.usbpayload",0
            	db "All Files",0,"*.*",0,0
Defextseem		db "seem",0             
Defextpayload	db "usbpayload",0             
isPayload		dd 0

P2kVolume		dd 0
CBIndex			dd 0

OldLVProc		dd 0
OldLBProc		dd 0
LBOriginalSizeY	dd 0
LVOriginalSizeY	dd 0
LBHoverSizeY	dd 0
LVHoverSizeY	dd 0

SeemStart		dd 0
SeemStop		dd 2ffh
RecordStart		dd 0
RecordStop		dd 3	
LVColumn0width	dd 0
LVColumn3width	dd 0
BatchAuto		dd 0

Bittable1		db 00000001b,00000010b,00000100b,00001000b,00010000b,00100000b,01000000b,10000000b
Bittable2		db 11111110b,11111101b,11111011b,11110111b,11101111b,11011111b,10111111b,01111111b

SeemList		dd 64 dup (0)  ; seem num /sem rec in dword, high word is seemnum
SeemAddrList	dd 64 dup (0)  ; pointer to seem data

FirstSeem		dd 0
ActualSeemByte	db 0
hSeemByte		dd 0
hBitCheckmark	dd 0
hByteBox		dd 0
hDiscard		dd 0

SeemNum			dd 0
SeemRec 		dd 0


CmdLog			db '\.log',0
CmdDelLog		db 255 dup (0)

szQ				db '"',0
CmdReport		db '\IPREPORT',0
Cmdlist			db '\SOURCEFILES',0
Cmdlist2		db '\DESTINATIONFILES',0
;CmdDelIpTemp	db 'cmd.exe /C "del c:\IPREPORT"',0
CmdDelIpTemp	db 'cmd.exe /C del "',0
CmdDelIp		db 512 dup (0)
;CmdIpTemp		db 'cmd.exe /C "ipconfig.exe /all >c:\IPREPORT"',0
CmdIpTemp		db 'cmd.exe /C ipconfig.exe /all >"',0
CmdIp			db 512 dup (0)
CmdListTemp		db 'cmd.exe /C dir /B/S/A-D "',0
CmdListTemp2	db '" >"',0
CmdList			db 512 dup (0)
;CmdSwitchTemp	db 'cmd.exe /C "echo at+mode=8 >COM6"',0
CmdSwitchTemp	db 'cmd.exe /C "echo at+mode="',0
CmdSwitchP2k	db 512 dup (0)
CmdSwitchLAN	db 512 dup (0)
CmdFtpDrive1	db '\FtpDrive\FtpDrive.reg"',0
CmdFtpDrive2	db '\FtpDrive\FtpDrive.exe"',0
CmdFtpServCp1	db 'cmd.exe /C copy /b "',0
CmdFtpServCp2	db '\FtpDrive\FtpServList1.txt" + "',0
CmdFtpServCp3	db '\ACTIP" "',0
CmdFtpServCp4	db '\FtpDrive\FtpServList.txt"',0
CmdTInsFtpDrive	db 'cmd.exe /C reg import "',0
CmdSambaOn1		db 'net use z: \\',0
CmdSambaOn2		db '\system /user:root /persistent:no',0
CmdSambaOn		db 512 dup (0)
CmdSambaOff		db 'net use z: /delete',0
;CmdTFtpDrive    db 'cmd.exe /C ',0
CmdInsFtpDrive	db 512 dup (0)
CmdFtpDrive	    db 512 dup (0)
CmdFtpServCp    db 512 dup (0)
phoneIP			db 512 dup (0)
localIP			db 512 dup (0)
LANStatus		dd 0
FtpDrivePID		dd 0
procAttr		SECURITY_ATTRIBUTES <PROCESS_TERMINATE>
LanDriveLetter  db "z:",0 
AlreadyMapped	dd 0
ThreadStarted	dd 0
startInfo		STARTUPINFO <0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>

hSocket			dd INVALID_SOCKET
wsaData			WSADATA <>
sockAddrTarget	sockaddr_in <>
sockAddrLocal	sockaddr_in <>

hex				dd 'A'-10

ezxBT			db "/ezxlocal/download/appwrite/setup/ezx_bluetooth.cfg",0
EzxModel		db 255 dup (0)
configCorrupted db 0