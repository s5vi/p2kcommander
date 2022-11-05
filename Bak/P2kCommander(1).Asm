.586
.model flat,stdcall
option casemap:none

include P2kCommander.inc
include P2kApi.inc
include P2kApi.asm
include Theme.inc

.code

start:

	invoke GetModuleHandle,NULL
	mov    hInstance,eax
	invoke GetCommandLine
	mov		CommandLine,eax
	invoke InitHyperLinkClass
	invoke InitCommonControls
	invoke WinMain,hInstance,NULL,CommandLine,SW_SHOWDEFAULT
	invoke ExitProcess,eax

WinMain proc hInst:HINSTANCE,hPrevInst:HINSTANCE,CmdLine:LPSTR,CmdShow:DWORD
	LOCAL	wc:WNDCLASSEX
	LOCAL	msg:MSG
	;
	; Init anigif lib
	;
	invoke InitAniGIF
	;
	; Check running instances
	;
;	invoke OpenMutex,MUTEX_ALL_ACCESS,FALSE,addr P2kInstance1
;	nop
;	.if eax!=0
;		;invoke CreateMutex, NULL, TRUE, addr P2kInstance2
;;		push eax
;		;invoke Sleep,3000
;;		pop ebx
;;		invoke CloseHandle,ebx
;		invoke DestroyWindow, hWnd          		
;		return 0  ; kill app          	
;	.else
;		invoke CreateMutex, NULL, TRUE, addr P2kInstance1
;		mov hMutex,eax	
;	.endif

	invoke BitmapFromResource,hInstance,501  ; about watermark jpg!!
	Mov 	hBackgr2, eax
	invoke BitmapFromResource,hInstance,503  ; about watermark jpg!!
	Mov 	hBackgr, eax
	invoke CreatePatternBrush,hBackgr	
	mov hBrushDwm,eax

	mov		wc.cbSize,sizeof WNDCLASSEX
	mov		wc.style,0 ;CS_HREDRAW or CS_VREDRAW
	mov		wc.lpfnWndProc,offset WndProc
	mov		wc.cbClsExtra,NULL
	mov		wc.cbWndExtra,DLGWINDOWEXTRA
	push	hInst
	pop		wc.hInstance
	mov		wc.hbrBackground,COLOR_BTNFACE+1
	mov		wc.lpszMenuName,IDM_MENU
	mov		wc.lpszClassName,offset ClassName
	invoke LoadIcon,NULL,IDI_APPLICATION
	mov		wc.hIcon,eax
	mov		wc.hIconSm,eax
	invoke LoadCursor,NULL,IDC_ARROW
	mov		wc.hCursor,eax
	invoke RegisterClassEx,addr wc
	
	invoke CreateDialogParam,hInstance,IDD_DIALOG,NULL,addr WndProc,NULL
	invoke ShowWindow,hWnd,SW_SHOWNORMAL
	invoke UpdateWindow,hWnd
	.while TRUE
;		invoke GetMessage,addr msg,NULL,0,0
;	  .BREAK .if !eax
;       invoke TranslateAccelerator,hWnd,hAccel,addr msg
;	  	invoke IsDialogMessage,hWnd,addr msg
;	  	.if !eax
;			invoke TranslateMessage,addr msg
;			invoke DispatchMessage,addr msg
;		.endif	
		invoke GetMessage,addr msg,NULL,0,0
	  .BREAK .if !eax
        invoke TranslateAccelerator,hWnd,hAccel,addr msg
		.if !eax
			invoke TranslateMessage,addr msg
			invoke DispatchMessage,addr msg
		.endif	
	.endw
	mov		eax,msg.wParam
	ret

WinMain endp

SetP2kCB1 proc hWin:HWND 
LOCAL sfi:SHFILEINFO
;ret
		invoke GetMsgAddr,116
		invoke SendDlgItemMessage,hWin,1005,CB_INSERTSTRING,0,eax ;addr P2kPattern ; add p2k drive /a
		invoke GetMsgAddr,117
		invoke SendDlgItemMessage,hWin,1005,CB_INSERTSTRING,1,eax ;addr P2kPattern ; add p2k drive /b
		invoke GetMsgAddr,118
		invoke SendDlgItemMessage,hWin,1005,CB_INSERTSTRING,2,eax ;addr P2kPattern ; add p2k drive /c
		invoke GetMsgAddr,119
		invoke SendDlgItemMessage,hWin,1005,CB_INSERTSTRING,3,eax ;addr P2kPattern ; add p2k drive /e
		invoke GetMsgAddr,115 ; seems
		invoke SendDlgItemMessage,hWin,1005,CB_INSERTSTRING,4,eax ;addr P2kPattern ; add p2k drive seem
		; set icon for p2k
;		.if P2kIconIndex!=0
;		    INVOKE SHGetFileInfo, addr szP2kC, 0, addr sfi, sizeof SHFILEINFO,SHGFI_SYSICONINDEX or SHGFI_SMALLICON or SHGFI_TYPENAME or SHGFI_ATTRIBUTES
;		    mov ebx,sfi.iIcon
;		    mov P2kIconIndex,ebx
;		.endif    
		invoke SendMessage,hLB1,CB_SETITEMDATA,0,P2kIconIndex
		invoke SendMessage,hLB1,CB_SETITEMDATA,4,P2kIconIndex
;	    INVOKE SHGetFileInfo,StrAddr("Templates\_.hlp"), 0, addr sfi, sizeof SHFILEINFO,SHGFI_SYSICONINDEX or SHGFI_SMALLICON or SHGFI_TYPENAME or SHGFI_ATTRIBUTES
;	    mov ebx,sfi.iIcon
		invoke SendMessage,hLB1,CB_SETITEMDATA,1,P2kQIconIndex
		invoke SendMessage,hLB1,CB_SETITEMDATA,2,P2kQIconIndex
		invoke SendMessage,hLB1,CB_SETITEMDATA,3,P2kQIconIndex
		invoke SendMessage,hLB1,CB_SETITEMDATA,4,P2kDIconIndex
	;fav
	invoke SendDlgItemMessage,hWin,1005,CB_ADDSTRING,0,addr Fav1
	invoke SendMessage,hLB1,CB_SETITEMDATA,eax,P2kIconIndex
		ret
SetP2kCB1 endp		
SetP2kCB2 proc hWin:HWND 
LOCAL sfi:SHFILEINFO
;ret
		invoke GetMsgAddr,116
		invoke SendDlgItemMessage,hWin,1006,CB_INSERTSTRING,0,eax ;addr P2kPattern ; add p2k drive /a
		invoke GetMsgAddr,117
		invoke SendDlgItemMessage,hWin,1006,CB_INSERTSTRING,1,eax ;addr P2kPattern ; add p2k drive /b
		invoke GetMsgAddr,118
		invoke SendDlgItemMessage,hWin,1006,CB_INSERTSTRING,2,eax ;addr P2kPattern ; add p2k drive /c
		invoke GetMsgAddr,119
		invoke SendDlgItemMessage,hWin,1006,CB_INSERTSTRING,3,eax ;addr P2kPattern ; add p2k drive /e
		invoke GetMsgAddr,115 ; seems
		invoke SendDlgItemMessage,hWin,1006,CB_INSERTSTRING,4,eax ;addr P2kPattern ; add p2k drive seem
		; set icon for p2k
;		.if P2kIconIndex!=0
;	    	INVOKE SHGetFileInfo, addr szP2kC, 0, addr sfi, sizeof SHFILEINFO,SHGFI_SYSICONINDEX or SHGFI_SMALLICON or SHGFI_TYPENAME or SHGFI_ATTRIBUTES
;		    mov ebx,sfi.iIcon
;		    mov P2kIconIndex,ebx
;		.endif 
		invoke SendMessage,hLB2,CB_SETITEMDATA,0,P2kIconIndex
		invoke SendMessage,hLB2,CB_SETITEMDATA,4,P2kIconIndex
;	    INVOKE SHGetFileInfo,StrAddr("c:\windows\unvise32.exe"), 0, addr sfi, sizeof SHFILEINFO,SHGFI_SYSICONINDEX or SHGFI_SMALLICON or SHGFI_TYPENAME or SHGFI_ATTRIBUTES
;	    mov ebx,sfi.iIcon
		invoke SendMessage,hLB2,CB_SETITEMDATA,1,P2kQIconIndex
		invoke SendMessage,hLB2,CB_SETITEMDATA,2,P2kQIconIndex
		invoke SendMessage,hLB2,CB_SETITEMDATA,3,P2kQIconIndex
		invoke SendMessage,hLB2,CB_SETITEMDATA,4,P2kDIconIndex
	;fav
	invoke SendDlgItemMessage,hWin,1006,CB_ADDSTRING,0,addr Fav1
	invoke SendMessage,hLB2,CB_SETITEMDATA,eax,P2kIconIndex
		ret
SetP2kCB2 endp		
ComputeLayout proc uses ebx hWin:HWND
			invoke GetWindowPlacement,hList1,addr ListPlacement1
			invoke GetWindowPlacement,hList2,addr ListPlacement2
			invoke GetWindowPlacement,hHead1,addr DirPlacement1
			invoke GetWindowPlacement,hHead2,addr DirPlacement2
			invoke GetWindowPlacement,hLB2,addr LBPlacement2
			invoke GetWindowPlacement,hReread2,addr RereadPlacement2

			mov eax,Wrect.right
			sub eax,Wrect.left
			mov ebx,ListPlacement1.rcNormalPosition.right
			sub ebx,ListPlacement1.rcNormalPosition.left
			sub eax,ebx
			.if  CARRY? || eax<225 
				mov eax,Wrect.right
				sub eax,Wrect.left
				sub eax,225
				mov ListPlacement1.rcNormalPosition.right,eax
				mov DirPlacement1.rcNormalPosition.right,eax
				add eax,4
				mov ListPlacement2.rcNormalPosition.left,eax
				mov DirPlacement2.rcNormalPosition.left,eax
				mov LBPlacement2.rcNormalPosition.left,eax
				add eax,134
				mov LBPlacement2.rcNormalPosition.right,eax
				inc eax
				mov RereadPlacement2.rcNormalPosition.left,eax
				add eax,75
				mov RereadPlacement2.rcNormalPosition.right,eax
				invoke SetWindowPlacement,hList1,addr ListPlacement1
				invoke SetWindowPlacement,hList2,addr ListPlacement2
				invoke SetWindowPlacement,hHead1,addr DirPlacement1
				invoke SetWindowPlacement,hHead2,addr DirPlacement2
				invoke SetWindowPlacement,hLB2,addr LBPlacement2
				invoke SetWindowPlacement,hReread2,addr RereadPlacement2
			.endif
			invoke SendMessage,hWin,WM_SIZING,WMSZ_TOP,offset Wrect			
			ret
ComputeLayout endp
ReadLangFile proc uses esi edi hWin:HWND  
	LOCAL	hFile:DWORD
	invoke lstrcpy,addr bufferx,addr LaunchDir
	invoke lstrcat,addr bufferx,addr szBackslash
	invoke lstrcat,addr bufferx,StrAddr("Messages.lng")
	invoke logstat,addr bufferx
	invoke CreateFile,addr bufferx,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	.if eax!=INVALID_HANDLE_VALUE
		mov	hFile,eax
		invoke GetFileSize,hFile,addr nBytes
		inc	eax
		mov	nBytes,eax
		invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
		mov	hMemLang,eax
		invoke ReadFile,hFile,hMemLang,nBytes,addr nBytes,FALSE
		invoke CloseHandle,hFile
		mov	nLangCount,0
		mov	esi,hMemLang
		.if esi
			mov	edi,esi
		  Nx:
			mov	al,[esi]
			cmp	al,0ah
			je @f
			.if byte ptr [esi]!=0dh
				mov	[edi],al
				inc	edi
			.endif
			inc	esi
			or al,al
			je Ex
			jmp	Nx
		  @@:
			inc	nLangCount
			mov	al,0
			mov	[edi],al
			inc	edi
			add	esi,1
			mov	al,[esi]
			or al,al
			jne	Nx
		  Ex:
			mov	[edi],al
			xor	eax,eax
		.endif
		mov	eax,nLangCount
		.if eax
			;Allocate memory for word pointers
			lea	eax,[eax*4+4]
			invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
			mov	hMemLangPtrs,eax
			mov	esi,hMemLang
			mov	edi,hMemLangPtrs
			;Setup word pointers
			.while byte ptr [esi] ; utolsó sorig
				.if byte ptr [esi]!="#"
					mov	[edi],esi
					add	edi,4
				.endif	
				.while byte ptr [esi] ; string vége 0-ig
					inc	esi
				.endw
				inc	esi
			.endw
		.endif
		mov eax,0
	.else
		invoke MessageBox,hWin,StrAddr ("Message file not found! Will exit now."),StrAddr ("Warning!"),MB_OK
		mov eax,-1	
	.endif
	ret
ReadLangFile endp
ReadFileList proc uses esi edi hWin:HWND  
	LOCAL	hFile:DWORD
	invoke lstrcpy,addr bufferx,addr LaunchDir
	invoke lstrcat,addr bufferx,addr szBackslash
	invoke lstrcat,addr bufferx,StrAddr("SOURCEFILES")
	;invoke logstat,addr bufferx
	invoke CreateFile,addr bufferx,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	.if eax!=INVALID_HANDLE_VALUE
		mov	hFile,eax
		invoke GetFileSize,hFile,addr nBytes
		inc	eax
		mov	nBytes,eax
		invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
		mov	hMemList,eax
		invoke ReadFile,hFile,hMemList,nBytes,addr nBytes,FALSE
		invoke CloseHandle,hFile
		mov	nFileCount,0
		mov	esi,hMemList
		.if esi
			mov	edi,esi
		  Nx:
			mov	al,[esi]
			cmp	al,0ah
			je @f
			.if byte ptr [esi]!=0dh
				mov	[edi],al
				inc	edi
			.endif
			inc	esi
			or al,al
			je Ex
			jmp	Nx
		  @@:
			inc	nFileCount
			mov	al,0
			mov	[edi],al
			inc	edi
			add	esi,1
			mov	al,[esi]
			or al,al
			jne	Nx
		  Ex:
			mov	[edi],al
			xor	eax,eax
		.endif
		mov	eax,nFileCount
		.if eax
			;Allocate memory for word pointers
			lea	eax,[eax*4+4]
			invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
			mov	hMemFilePtrs,eax
			mov	esi,hMemList
			mov	edi,hMemFilePtrs
			;Setup word pointers
			.while byte ptr [esi] ; utolsó sorig
				.if byte ptr [esi]!="#"
					mov	[edi],esi
					add	edi,4
				.endif	
				.while byte ptr [esi] ; string vége 0-ig
					inc	esi
				.endw
				inc	esi
			.endw
		.endif
		mov eax,0
	.else
		invoke MessageBox,hWin,StrAddr ("SOURCEFILELIST file not found! Will exit now."),StrAddr ("Warning!"),MB_OK
		mov eax,-1	
	.endif
	ret
ReadFileList endp
ReadIpFile proc uses esi edi hWin:HWND  
	LOCAL	hFile:DWORD
	invoke Sleep,500
	invoke lstrcpy,addr bufferx,addr LaunchDir
	invoke lstrcat,addr bufferx,StrAddr("\IPREPORT")
	invoke CreateFile,addr bufferx,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	.if eax!=INVALID_HANDLE_VALUE
		mov	hFile,eax
		invoke GetFileSize,hFile,addr nBytes
		inc	eax
		mov	nBytes,eax
		invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
		mov	hMemList,eax
		invoke ReadFile,hFile,hMemList,nBytes,addr nBytes,FALSE
		invoke CloseHandle,hFile
		
		invoke BinSearch,0,hMemList,nBytes,StrAddr("Motorola"),8
		.if eax==-1
			invoke BinSearch,0,hMemList,nBytes,StrAddr("Belcarra"),8
			.if eax==-1
				invoke BinSearch,0,hMemList,nBytes,StrAddr("USBLAN"),6 ;
			.endif	
		.endif	
		.if eax!=-1
			mov esi,hMemList
			add esi,eax
			push esi
			.while byte ptr [esi]!=0dh
				inc esi
			.endw
			mov byte ptr [esi],0
			pop esi
			invoke logstat,esi
			.while word ptr [esi]!="PI"
				inc esi
			.endw
			.if word ptr [esi+2]=="6v" ; Vista with IPv6?
				inc esi
				.while word ptr [esi]!="PI"
					inc esi
				.endw
			.endif
			inc esi
			.while byte ptr [esi]!=":"
				inc esi
			.endw
			inc esi
			.while byte ptr [esi]==" "
				inc esi
			.endw
			push esi
			.while byte ptr [esi]!=0dh && byte ptr [esi]<':' && byte ptr [esi]>',' 
				inc esi
			.endw
			mov byte ptr [esi],0
			pop esi
			push esi
			invoke lstrcpy,addr localIP,esi
			pop esi
			invoke logstat,esi
			mov _DevIF,1
			;
			; Found, launch smb/ftp  or P2k05 over USBLAN
			;
			.if isFixIP==1 ;only this
				invoke lstrcpy,addr phoneIP,addr actIP
			.else
				invoke lstrcpy,addr phoneIP,addr localIP
				mov esi,offset phoneIP
				invoke lstrlen,esi
				dec esi
				add esi,eax
				inc byte ptr [esi]
			.endif
			.if isUSBLAN==1 ;&& AlreadyMapped==0 ; smb
				; compose IP addr and command
				;invoke logstat,StrAddr("Connecting...")
				invoke lstrcpy,addr CmdSambaOn,addr CmdSambaOn1
				invoke lstrcat,addr CmdSambaOn,addr phoneIP
				invoke lstrcat,addr CmdSambaOn,addr CmdSambaOn2
				invoke logstat,StrAddr ("Connecting...") ;addr CmdSambaOn
				mov startInfo.dwFlags,STARTF_USESHOWWINDOW
				mov startInfo.wShowWindow,SW_HIDE
				invoke CreateProcess,NULL,addr CmdSambaOn,NULL,NULL,FALSE,\ 
		              NORMAL_PRIORITY_CLASS,\ 
		              NULL,NULL,ADDR startInfo,ADDR processInfo
				mov startInfo.wShowWindow,SW_SHOW
				invoke Sleep,5000
						mov CBIndex,6
						.while CBIndex>5
							invoke SendMessage,hLB1,CB_DELETESTRING,5,0
							invoke SendMessage,hLB2,CB_DELETESTRING,5,0
							mov CBIndex,eax
						.endw		
				invoke logstat,StrAddr("Phone filesystem mapped at 'Z:'")
	;			; get drive list
				invoke GetDrives1
				invoke GetDrives2
				mov AlreadyMapped,1
			.endif	
			.if isUSBLAN==2 && AlreadyMapped==0 ; ftp
				; prepare FtpDrive/FtpServList.txt
				; save IP to file ACTIP
				invoke lstrcpy,addr bufferx,addr szQ
				invoke lstrcat,addr bufferx,addr LaunchDir
				invoke lstrcat,addr bufferx,addr szBackslash
				invoke lstrcat,addr bufferx,StrAddr("ACTIP")
				invoke lstrcat,addr bufferx,addr szQ
				invoke DeleteFile,offset bufferx
				invoke CreateFile,offset bufferx,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0
				mov hSaveFile,eax
				invoke lstrlen,addr phoneIP
				invoke WriteFile,hSaveFile,addr phoneIP,eax,addr writtenb,0
				invoke WriteFile,hSaveFile,addr crlf,2,addr writtenb,0
				invoke CloseHandle,hSaveFile
				; run copy command
				mov startInfo.dwFlags,STARTF_USESHOWWINDOW
				mov startInfo.wShowWindow,SW_HIDE
				invoke CreateProcess,NULL,addr CmdFtpServCp,addr procAttr ,NULL,FALSE,\ 
		              NORMAL_PRIORITY_CLASS,\ 
		              NULL,NULL,ADDR startInfo,ADDR processInfo
				mov startInfo.wShowWindow,SW_SHOW
;				invoke logstat,addr CmdFtpServCp
				; run ftpdrive 			
				mov startInfo.dwFlags,STARTF_USESHOWWINDOW
				mov startInfo.wShowWindow,SW_HIDE
				invoke CreateProcess,NULL,addr CmdFtpDrive,addr procAttr ,NULL,FALSE,\ 
		              NORMAL_PRIORITY_CLASS,\ 
		              NULL,NULL,ADDR startInfo,ADDR processInfo
				mov startInfo.wShowWindow,SW_SHOW
				mov eax, processInfo.hProcess
				mov FtpDrivePID,eax

				;invoke logstat,addr bufferx
				;invoke logstat,addr CmdFtpServCp
				;invoke logstat,addr CmdFtpDrive
				invoke Sleep,2000
						mov CBIndex,6
						.while CBIndex>5
							invoke SendMessage,hLB1,CB_DELETESTRING,5,0
							invoke SendMessage,hLB2,CB_DELETESTRING,5,0
							mov CBIndex,eax
						.endw		
	;			; get drive list
				invoke GetDrives1
				invoke GetDrives2
				invoke logstat,StrAddr("Phone filesystem mapped at 'Z:'")
				mov AlreadyMapped,1
			.elseif isUSBLAN==3
;				invoke logstat,StrAddr("PhoneIP:")
;				invoke logstat,addr phoneIP
;				invoke logstat,StrAddr("LocalIP:")
;				invoke logstat,addr localIP
				mov LANStatus,1
				;
				; Start and connect sockets
				;
				.if isVerboseLog==1
					invoke logstat,StrAddr ("Phone IP address is:")
					invoke logstat,addr phoneIP
				.endif
				invoke logstat,StrAddr("Initializing TCP/IP interface.")
				;
				; init Winsock2
				;
				invoke  WSAStartup, REQ_WINSOCK_VER, addr wsaData
				.if eax!=0
					invoke MessageBox,hWin,StrAddr("!! Cannot initialize Winsock2."),StrAddr("---- Error ----"),MB_OK+MB_ICONERROR
					invoke SendMessage,hWin,WM_CLOSE,0,0 
				.endif
				;
				; Create Socket
				;
				invoke	socket, AF_INET, SOCK_STREAM, IPPROTO_TCP
				.if eax==INVALID_SOCKET
					invoke MessageBox,hWin,StrAddr("!! Cannot create a socket."),StrAddr("---- Error ----"),MB_OK+MB_ICONERROR
					invoke SendMessage,hWin,WM_CLOSE,0,0 
				.endif
				mov hSocket,eax
				;
				; fill sockAddr structures
				;
				mov sockAddrTarget.sin_family,AF_INET
				mov	ecx,SERVER_PORT
				xchg 	cl, ch	; convert to network byte order
				mov sockAddrTarget.sin_port,cx
				invoke inet_addr, addr phoneIP
				mov sockAddrTarget.sin_addr.S_un.S_addr,eax
				mov sockAddrLocal.sin_family,AF_INET
				mov sockAddrLocal.sin_port,0
				invoke inet_addr, addr localIP
				mov sockAddrLocal.sin_addr.S_un.S_addr,eax
				;
				; Bind Socket to USBLAN IP address
				;
				;DbgDump offset localIP,32
				;DbgDump offset phoneIP,32
				invoke bind,hSocket,addr sockAddrLocal, sizeof sockAddrLocal
				.if eax!=0
					invoke logstat,StrAddr("!! Cannot bind socket to USBLAN IP address.")
				.endif
				;
				; Connect Socket
				;
				invoke 	connect, hSocket, addr sockAddrTarget, sizeof sockAddrTarget
				;
				; Done
				;
				mov isP2k05,1
				mov ManualP2k05,1
				.if eax!=0
					invoke logstat,StrAddr("!! Cannot connect socket.")
				.else 
					invoke logstat,StrAddr("*** Connection successful.")
					invoke P2K_Vibrate
					.if isFileFilter==0
						mov isFileFilter,1
						invoke lstrcpy,addr FileFilter,StrAddr("/a/*")
					.endif		
					invoke GetVolInfoShort
					invoke UpdateDropdown
				.endif
				
			.endif
			;mov DevFound,1
			;mov LANStatus,1
		.else	
			mov _DevIF,0
			;mov DevFound,0
			;mov LANStatus,0
		.endif
		invoke GlobalFree,hMemList
		ret
	.else
		mov _DevIF,0
;		invoke MessageBox,hWin,StrAddr ("IPREPORT file not found!"),StrAddr ("Warning!"),MB_OK
		mov eax,-1	
	.endif
	ret
ReadIpFile endp
ReadSeemList proc uses esi edi hWin:HWND  
	LOCAL	hFile:DWORD
	invoke lstrcpy,addr bufferx,addr LaunchDir
	invoke lstrcat,addr bufferx,addr szBackslash
	invoke lstrcat,addr bufferx,StrAddr("Seem.lst")
	invoke CreateFile,addr bufferx,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	.if eax!=INVALID_HANDLE_VALUE
		mov	hFile,eax
		invoke GetFileSize,hFile,addr nBytes
		inc	eax
		mov	nBytes,eax
		invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
		mov	hMemSeem,eax
		invoke ReadFile,hFile,hMemSeem,nBytes,addr nBytes,FALSE
		invoke CloseHandle,hFile
		mov	nSeemCount,0
		mov	esi,hMemSeem
		.if esi
			mov	edi,esi
		  Nx:
			mov	al,[esi]
			cmp	al,0ah
			je @f
			.if byte ptr [esi]!=0dh
				mov	[edi],al
				inc	edi
			.endif
			inc	esi
			or al,al
			je Ex
			jmp	Nx
		  @@:
			inc	nSeemCount
			mov	al,0
			mov	[edi],al
			inc	edi
			add	esi,1
			mov	al,[esi]
			or al,al
			jne	Nx
		  Ex:
			mov	[edi],al
			xor	eax,eax
		.endif
		mov	eax,nSeemCount
		.if eax
			;Allocate memory for word pointers
			lea	eax,[eax*4+4]
			invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
			mov	hMemSeemPtrs,eax
			mov	esi,hMemSeem
			mov	edi,hMemSeemPtrs
			;Setup word pointers
			.while byte ptr [esi] ; utolsó sorig
				.if byte ptr [esi]!="#"
					mov	[edi],esi
					add	edi,4
				.endif	
				.while byte ptr [esi] ; string vége 0-ig
					inc	esi
				.endw
				inc	esi
			.endw
		.endif
		mov eax,0
	.else
		invoke MessageBox,hWin,StrAddr ("Seem list file not found!"),StrAddr ("Warning!"),MB_OK
		mov eax,-1	
	.endif
	ret
ReadSeemList endp
ReadSeemCat proc uses esi edi hWin:HWND  
	LOCAL	hFile:DWORD
	invoke lstrcpy,addr bufferx,addr LaunchDir
	invoke lstrcat,addr bufferx,addr szBackslash
	invoke lstrcat,addr bufferx,StrAddr("SeemCategories.lst")
	invoke CreateFile,addr bufferx,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	.if eax!=INVALID_HANDLE_VALUE
		mov	hFile,eax
		invoke GetFileSize,hFile,addr nBytes
		inc	eax
		mov	nBytes,eax
		invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
		mov	hMemSeemF,eax
		invoke ReadFile,hFile,hMemSeemF,nBytes,addr nBytes,FALSE
		invoke CloseHandle,hFile
		mov	nSeemFCount,0
		mov	esi,hMemSeemF
		.if esi
			mov	edi,esi
		  Nx:
			mov	al,[esi]
			cmp	al,0ah
			je @f
			.if byte ptr [esi]!=0dh
				mov	[edi],al
				inc	edi
			.endif
			inc	esi
			or al,al
			je Ex
			jmp	Nx
		  @@:
			inc	nSeemFCount
			mov	al,0
			mov	[edi],al
			inc	edi
			add	esi,1
			mov	al,[esi]
			or al,al
			jne	Nx
		  Ex:
			mov	[edi],al
			xor	eax,eax
		.endif
		mov	eax,nSeemFCount
		.if eax
			;Allocate memory for word pointers
			lea	eax,[eax*4+4]
			invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
			mov	hMemSeemFPtrs,eax
			mov	esi,hMemSeemF
			mov	edi,hMemSeemFPtrs
			;Setup word pointers
			.while byte ptr [esi] ; utolsó sorig
				.if byte ptr [esi]!="#"
					mov	[edi],esi
					add	edi,4
				.endif	
				.while byte ptr [esi] ; string vége 0-ig
					inc	esi
				.endw
				inc	esi
			.endw
		.endif
		mov eax,0
	.else
		invoke MessageBox,hWin,StrAddr ("Seem categories file not found!"),StrAddr ("Warning!"),MB_OK
		mov eax,-1	
	.endif
	ret
ReadSeemCat endp
ReadHiddenList proc uses esi edi hWin:HWND  
	LOCAL	hFile:DWORD
	invoke lstrcpy,addr bufferx,addr LaunchDir
	invoke lstrcat,addr bufferx,addr szBackslash
	invoke lstrcat,addr bufferx,StrAddr("Hidden_files.lst")
	invoke CreateFile,addr bufferx,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	.if eax!=INVALID_HANDLE_VALUE
		mov	hFile,eax
		invoke GetFileSize,hFile,addr nBytes
		inc	eax
		mov	nBytes,eax
		invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
		mov	hMemHiddenF,eax
		invoke ReadFile,hFile,hMemHiddenF,nBytes,addr nBytes,FALSE
		invoke CloseHandle,hFile
		mov	nHiddenFCount,0
		mov	esi,hMemHiddenF
		.if esi
			mov	edi,esi
		  Nx:
			mov	al,[esi]
			cmp	al,0ah
			je @f
			.if byte ptr [esi]!=0dh
				mov	[edi],al
				inc	edi
			.endif
			inc	esi
			or al,al
			je Ex
			jmp	Nx
		  @@:
			inc	nHiddenFCount
			mov	al,0
			mov	[edi],al
			inc	edi
			add	esi,1
			mov	al,[esi]
			or al,al
			jne	Nx
		  Ex:
			mov	[edi],al
			xor	eax,eax
		.endif
		mov	eax,nHiddenFCount
		.if eax
			;Allocate memory for word pointers
			lea	eax,[eax*4+4]
			invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
			mov	hMemHiddenFPtrs,eax
			mov	esi,hMemHiddenF
			mov	edi,hMemHiddenFPtrs
			;Setup word pointers
			.while byte ptr [esi] ; utolsó sorig
				.if byte ptr [esi]!="#"
					mov	[edi],esi
					add	edi,4
				.endif	
				.while byte ptr [esi] ; string vége 0-ig
					inc	esi
				.endw
				inc	esi
			.endw
		.endif
		mov eax,0
	.else
		invoke MessageBox,hWin,StrAddr ("List of hidden files not found!"),StrAddr ("Warning!"),MB_OK
		mov eax,-1	
	.endif
	ret
ReadHiddenList endp
ReadFunctions proc uses esi edi ebx ecx hWin:HWND  
LOCAL	hFile:DWORD
LOCAL lvc:LV_COLUMN 
LOCAL sfi:SHFILEINFO
LOCAL lvi:LV_ITEM
LOCAL row:DWORD
LOCAL Seemnum:DWORD
LOCAL Seemrec:DWORD
LOCAL Seemoffs:DWORD
LOCAL Seembit:DWORD
LOCAL Dash:Byte
	mov row,0
	invoke EnableWindow,hDiscard,FALSE
	invoke EnableWindow,hWrite,FALSE
	; fill SeemList with 0 128*4 byte
	mov edi,offset SeemList
	mov ecx,128*4
	mov al,0
	rep stosb
	; setup listview 1851
	invoke GetDlgItem,hWin,1851
	mov hListSeem,eax
	invoke SendMessage,hListSeem,LVM_DELETEALLITEMS,0,0
	invoke SendMessage,hListSeem,LVM_DELETECOLUMN,4,0
	invoke SendMessage,hListSeem,LVM_DELETECOLUMN,3,0
	invoke SendMessage,hListSeem,LVM_DELETECOLUMN,2,0
	invoke SendMessage,hListSeem,LVM_DELETECOLUMN,1,0
	invoke SendMessage,hListSeem,LVM_DELETECOLUMN,0,0
    mov     eax, LVS_EX_FULLROWSELECT or LVS_EX_HEADERDRAGDROP or\
	                      LVS_EX_SUBITEMIMAGES or LVS_EX_GRIDLINES or LVS_EX_LABELTIP
    INVOKE     SendMessage, hListSeem, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, eax
    INVOKE     SendMessage, hListSeem, WM_SETFONT, hFontL, 1
    ;INVOKE     SendMessage, hListSeem, LVM_SETTEXTBKCOLOR, 0, 0ffc0c0h
    ; create checkmark imagelist and bind to LV
	invoke ImageList_Create,16,16,ILC_COLOR24 OR ILC_MASK,0,4
	mov hImageListC,eax
	invoke LoadIcon,hInstance,4950
	invoke ImageList_AddIcon,hImageListC,eax
	invoke LoadIcon,hInstance,4951
	invoke ImageList_AddIcon,hImageListC,eax
	invoke LoadIcon,hInstance,4952
	invoke ImageList_AddIcon,hImageListC,eax
	invoke LoadIcon,hInstance,4953
	invoke ImageList_AddIcon,hImageListC,eax
    INVOKE     SendMessage, hListSeem, LVM_SETIMAGELIST, LVSIL_SMALL, hImageListC
	mov lvc.imask,LVCF_TEXT+LVCF_WIDTH
	invoke GetMsgAddr,127
	mov lvc.pszText,eax ;offset Heading1
	mov lvc.lx,48 ;+16 ;43
	invoke SendMessage,hListSeem, LVM_INSERTCOLUMN,1,addr lvc
	or lvc.imask,LVCF_FMT
	mov lvc.fmt,LVCFMT_RIGHT
	invoke GetMsgAddr,128
	mov lvc.pszText,eax ;offset Heading2
	mov lvc.lx,44 ;40
	invoke SendMessage,hListSeem, LVM_INSERTCOLUMN, 2 ,addr lvc	
	invoke GetMsgAddr,129
	mov lvc.pszText,eax ;offset Heading4
	mov lvc.lx,40 ;35
	mov lvc.fmt,LVCFMT_LEFT
	invoke SendMessage,hListSeem, LVM_INSERTCOLUMN, 3 ,addr lvc	
	invoke GetMsgAddr,130
	mov lvc.pszText,eax ;offset Heading4
	mov lvc.lx,32 ;28
	mov lvc.fmt,LVCFMT_LEFT
	invoke SendMessage,hListSeem, LVM_INSERTCOLUMN, 4 ,addr lvc	
	invoke GetMsgAddr,131
	mov lvc.pszText,eax ;offset Heading4
	mov lvc.lx,297-18-16+140+16
	mov lvc.fmt,LVCFMT_LEFT
	invoke SendMessage,hListSeem, LVM_INSERTCOLUMN, 0 ,addr lvc	
		
	invoke lstrcpy,addr bufferx,addr LaunchDir
	invoke lstrcat,addr bufferx,addr szBackslash
	.if isP2k05==0
		invoke lstrcat,addr bufferx,StrAddr("SeemFunctionsP2k.csv")
	.else
		invoke lstrcat,addr bufferx,StrAddr("SeemFunctionsP2k05.csv")
	.endif		
	invoke CreateFile,addr bufferx,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	.if eax!=INVALID_HANDLE_VALUE
		mov	hFile,eax
		invoke GetFileSize,hFile,addr nBytes
		inc	eax
		mov	nBytes,eax
		invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
		mov	hMemF,eax
		invoke ReadFile,hFile,hMemF,nBytes,addr nBytes,FALSE
		invoke CloseHandle,hFile
		mov	nFCount,0
		mov	esi,hMemF
		.if esi
			mov	edi,esi
		  Nx:
			mov	al,[esi]
			cmp	al,0ah
			je @f
			.if byte ptr [esi]!=0dh
				mov	[edi],al
				inc	edi
			.endif
			inc	esi
			or al,al
			je Ex
			jmp	Nx
		  @@:
			inc	nFCount
			mov	al,0
			mov	[edi],al
			inc	edi
			add	esi,1
			mov	al,[esi]
			or al,al
			jne	Nx
		  Ex:
			mov	[edi],al
			xor	eax,eax
		.endif
		mov	eax,nFCount
		.if eax
			;Allocate memory for word pointers
			lea	eax,[eax*4+4]
			invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
			mov	hMemFPtrs,eax
			mov	esi,hMemF
			mov	edi,hMemFPtrs
			;Setup word pointers
			.while byte ptr [esi] ; utolsó sorig
				.if byte ptr [esi]!="#"
					mov	[edi],esi
					add	edi,4
				.endif	
				.while byte ptr [esi] ; string vége 0-ig
					inc	esi
				.endw
				inc	esi
			.endw
		.endif
		mov	edx,hMemFPtrs
		.while dword ptr [edx]
			mov esi,[edx]
			push edx
			; fill listview
		    mov lvi.imask, LVIF_TEXT or LVIF_IMAGE or LVIF_PARAM 
			push row
			pop lvi.iItem	
			mov lvi.iSubItem,0
			push row
			pop lvi.lParam
			;.while byte ptr [esi]!=';'
			;	inc esi
			;.endw
			;inc esi
			mov edi,esi
			.while byte ptr [edi]!=';'
				inc edi
			.endw
			mov byte ptr [edi],0
			inc edi
			mov lvi.pszText,esi
			mov eax,P2kIconIndex
		    mov     lvi.iImage, 0
			invoke SendMessage,hListSeem, LVM_INSERTITEM,0, addr lvi
			invoke htodw,esi
			mov Seemnum,eax		; save seem num
			inc lvi.iSubItem
			mov lvi.imask,LVIF_TEXT
			mov lvi.pszText,esi
			invoke SendMessage,hListSeem, LVM_SETITEM,0, addr lvi
			inc lvi.iSubItem
			mov esi,edi
			;.while byte ptr [esi]!=';'
			;	inc esi
			;.endw
			;inc esi
			mov edi,esi
			.while byte ptr [edi]!=';'
				inc edi
			.endw
			mov byte ptr [edi],0
			inc edi
			mov lvi.imask,LVIF_TEXT
			invoke htodw,esi
			mov Seemrec,eax  		; save seem rec
			mov lvi.pszText,esi
			invoke SendMessage,hListSeem, LVM_SETITEM,0, addr lvi
			inc lvi.iSubItem
			mov esi,edi
			;.while byte ptr [esi]!=';'
			;	inc esi
			;.endw
			;inc esi
			mov edi,esi
			.while byte ptr [edi]!=';'
				inc edi
			.endw
			mov byte ptr [edi],0
			inc edi
			mov lvi.imask,LVIF_TEXT
			mov lvi.pszText,esi
			mov al,[esi]
			mov Dash,al
			invoke htodw,esi
			mov Seemoffs,eax  		; save seem offs
			invoke SendMessage,hListSeem, LVM_SETITEM,0, addr lvi
			inc lvi.iSubItem
			mov esi,edi
			;.while byte ptr [esi]!=';'
			;	inc esi
			;.endw
			;inc esi
			mov edi,esi
			.while byte ptr [edi]!=';'
				inc edi
			.endw
			mov byte ptr [edi],0
			inc edi
			mov lvi.imask,LVIF_TEXT
			mov lvi.pszText,esi
			invoke htodw,esi
			mov Seembit,eax  		; save seem bit
			invoke SendMessage,hListSeem, LVM_SETITEM,0, addr lvi
			mov lvi.iSubItem,0
			mov esi,edi
			;.while byte ptr [esi]!=';'
			;	inc esi
			;.endw
			mov lvi.imask,LVIF_TEXT
			mov lvi.pszText,esi
			invoke SendMessage,hListSeem, LVM_SETITEM,0, addr lvi
			; rip seem number and rec
			mov ecx,Seemrec ; rec
			mov eax,Seemnum ; seem
			shl eax,16
			mov ax,cx ; composite num/rec
			; search table
			mov ebx,offset SeemList ; a mem table which contains seem numbers and records
			.while [ebx]!=eax
				.if dword ptr [ebx]==0
					.break
				.endif
				add ebx,4
			.endw
			.if dword ptr [ebx]==0
				; not found append item to the table
				mov [ebx],eax
				; read new seem into mem
				.if _DevIF!=0
					invoke ReadFunctionSeems,Seemnum,Seemrec
				.endif
			.else	
				; found
			.endif
			; get seem bit and display
		    mov lvi.imask, LVIF_IMAGE
			mov lvi.iSubItem,0
			.if _DevIF!=0
				invoke GetSeemBit,Seemnum,Seemrec,Seemoffs,Seembit
			.endif	
			.if eax==0
			    mov     lvi.iImage, 1
			.else	
			    mov     lvi.iImage, 2
			.endif
			.if _DevIF==0
			    mov     lvi.iImage, 0
			.endif
			.if Dash=="-"
			    mov     lvi.iImage, 3
			.endif
			invoke SendMessage,hListSeem, LVM_SETITEM,0, addr lvi
			; get the next row			
			inc row
			pop edx
			add	edx,4
		.endw
		;DbgDump offset SeemList,32
		invoke GlobalFree,hMemF
		invoke GlobalFree,hMemFPtrs
		mov eax,0
	.else
		invoke MessageBox,hWin,StrAddr ("Functions excel file not found!"),StrAddr ("Warning!"),MB_OK
		mov eax,-1	
	.endif
	.if _DevIF!=0
		mov FirstSeem,1
	.endif	
;	DbgDump offset SeemAddrList,32
;	mov esi,offset SeemAddrList
;	DbgDump [esi],32
;	add esi,4
;	DbgDump [esi],32
;	add esi,4
;	DbgDump [esi],32
;	add esi,4
;	DbgDump [esi],32
	ret
ReadFunctions endp
ReadFunctionSeems proc uses edi esi ecx ebx Seem:DWORD,Rec:DWORD
				mov edi,offset SeemAddrList
				.while dword ptr [edi]!=0 ; find next free slot
					add edi,4
				.endw
				push offset seem_data
				push 0
				push 0
				push Rec
				push Seem
				invoke Cmd_RDELEM
				mov eax,seem_read_bytes
				;dec eax
				push eax
				invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
				;invoke GlobalLock,eax
				mov [edi],eax
				; memcpy
				pop ecx
				mov ebx,offset seem_data
				inc ebx
				;push eax
				invoke CopyMemory,eax,ebx,ecx
				;mov esi,offset SeemAddrList
				;pop eax
				;DbgDump eax,32
				;DbgDump ebx,32
				;mov edi,offset SeemAddrList
				;DbgDump edi,32
				ret
ReadFunctionSeems endp
GetSeemBit proc Seem:DWORD,Rec:DWORD,Offs:DWORD,Bit:DWORD
				mov eax,Seem
				mov ecx,Rec
				shl eax,16
				mov ax,cx ; seem/rec combo
				mov esi, offset SeemList
				mov edi, offset SeemAddrList
				; search table
				.while [esi]!=eax
					add esi,4
					add edi,4
				.endw
				mov esi,[edi]
				add esi,Offs
				mov al,[esi]
				mov ActualSeemByte,al
				mov esi,offset Bittable1
				add esi,Bit
				and al,[esi]
				.if al!=0
					mov eax,1
				.else
					mov eax,0	
				.endif
				ret
GetSeemBit endp
SetSeemBit proc Val:DWORD,Seem:DWORD,Rec:DWORD,Offs:DWORD,Bit:DWORD
				mov eax,Seem
				mov ecx,Rec
				shl eax,16
				mov ax,cx ; seem/rec combo
				mov esi, offset SeemList
				mov edi, offset SeemAddrList
				; search table
				.while [esi]!=eax
					add esi,4
					add edi,4
				.endw
				mov esi,[edi]
				add esi,Offs
				mov al,[esi]
				.if Val==0
					mov edi,offset Bittable2
					add edi,Bit
					and al,[edi]
					mov [esi],al
				.else
					mov edi,offset Bittable1
					add edi,Bit
					or al,[edi]
					mov [esi],al
				.endif
				ret
SetSeemBit endp
ToggleSeemBit proc Seem:DWORD,Rec:DWORD,Offs:DWORD,Bit:DWORD
;				invoke GetSeemBit,Seem,Rec,Offs,Bit
;				xor eax,1
;				invoke SetSeemBit,eax,Seem,Rec,Offs,Bit
				mov eax,Seem
				mov ecx,Rec
				shl eax,16
				mov ax,cx ; seem/rec combo
				mov esi, offset SeemList
				mov edi, offset SeemAddrList
				; search table
				.while [esi]!=eax
					add esi,4
					add edi,4
				.endw
				mov esi,[edi]
				add esi,Offs
				mov al,[esi]
				mov edi,offset Bittable1
				add edi,Bit
				xor al,[edi]
				mov [esi],al
				ret
ToggleSeemBit endp
;SetCheckmarks proc
;LOCAL Seemnum:DWORD
;LOCAL Seemrec:DWORD
;LOCAL Seemoffs:DWORD
;LOCAL Seembit:DWORD
;LOCAL LVCount:DWORD
;
;		  		; loop thru LV items
;				invoke SendMessage,hListSeem,LVM_GETITEMCOUNT,0,0
;				mov LVCount,eax
;				mov _lvi.iItem,-1
;				mov _lvi.cchTextMax,256
;				mov _lvi.imask,LVIF_TEXT
;				mov eax,offset bufferx
;				mov _lvi.pszText,eax
;				mov eax,_lvi.iItem
;				.while eax!=LVCount
;					; get seem data
;					mov _lvi.iSubItem,1
;					inc _lvi.iItem
;					mov _lvi.imask,LVIF_TEXT
;					invoke SendMessage,hListSeem,LVM_GETITEM,0,addr _lvi   ; buffer:filename
;					invoke htodw,addr bufferx
;					mov Seemnum,eax
;					inc _lvi.iSubItem
;					mov _lvi.imask,LVIF_TEXT
;					invoke SendMessage,hListSeem,LVM_GETITEM,0,addr _lvi   ; buffer:filename
;					invoke htodw,addr bufferx
;					mov Seemrec,eax
;					inc _lvi.iSubItem
;					mov _lvi.imask,LVIF_TEXT
;					invoke SendMessage,hListSeem,LVM_GETITEM,0,addr _lvi   ; buffer:filename
;					invoke htodw,addr bufferx
;					mov Seemoffs,eax
;					inc _lvi.iSubItem
;					mov _lvi.imask,LVIF_TEXT
;					invoke SendMessage,hListSeem,LVM_GETITEM,0,addr _lvi   ; buffer:filename
;					invoke htodw,addr bufferx
;					mov Seembit,eax
;					; read byte
;			        push    offset bufferx
;	                mov eax,Seemoffs
;	                inc eax
;	                push eax
;	                push    0
;	                push    Seemrec
;	                push    Seemnum
;	                invoke Cmd_RDELEM
;	                mov eax,seem_read_bytes
;	                mov esi,offset bufferx
;	                add esi,Seemoffs
;	                inc esi
;	                mov eax,0
;	                mov al,[esi]
;					; display bit
;					mov esi,offset Bittable1
;					add esi,Seembit
;					and al,[esi]
;					.if al==0
;						mov _lvi.iImage,1
;					.else
;						mov _lvi.iImage,2
;					.endif	
;					mov _lvi.iSubItem,0
;				    mov _lvi.imask, LVIF_IMAGE
;					invoke SendMessage,hListSeem, LVM_SETITEM,0, addr _lvi
;					mov eax,_lvi.iItem
;				.endw
;				ret
;SetCheckmarks endp
FreeSeemMem proc uses edi
			mov edi,offset SeemAddrList
			.while dword ptr [edi]!=0
				invoke GlobalFree,[edi]
				add edi,4
			.endw
			ret
FreeSeemMem endp
GetMsgAddr proc uses esi index:DWORD
			mov eax,index 
			shl eax,2   ;*4
			mov esi,hMemLangPtrs
			add esi,eax
			mov eax,[esi]
			ret
GetMsgAddr endp
SetButtonLabels proc hWin:HWND
			invoke GetMsgAddr,90
			invoke SendDlgItemMessage,hWin,1012,WM_SETTEXT,0,eax
			invoke GetMsgAddr,90
			invoke SendDlgItemMessage,hWin,1013,WM_SETTEXT,0,eax
			invoke GetMsgAddr,91
			invoke SendDlgItemMessage,hWin,1007,WM_SETTEXT,0,eax
			invoke GetMsgAddr,92
			invoke SendDlgItemMessage,hWin,1026,WM_SETTEXT,0,eax
			invoke GetMsgAddr,93
			invoke SendDlgItemMessage,hWin,1008,WM_SETTEXT,0,eax
			invoke GetMsgAddr,94
			invoke SendDlgItemMessage,hWin,1010,WM_SETTEXT,0,eax
			invoke GetMsgAddr,95
			invoke SendDlgItemMessage,hWin,1004,WM_SETTEXT,0,eax
			invoke GetMsgAddr,96
			invoke SendDlgItemMessage,hWin,1027,WM_SETTEXT,0,eax
			invoke GetMsgAddr,97
			invoke SendDlgItemMessage,hWin,1009,WM_SETTEXT,0,eax
			invoke GetMsgAddr,98
			invoke SendDlgItemMessage,hWin,1011,WM_SETTEXT,0,eax
			ret
SetButtonLabels endp

AttrProc PROC uses ebx esi edx hWin:HWND,iMsg:DWORD,wParam:WPARAM, lParam:LPARAM
LOCAL lvi:LV_ITEM
LOCAL buffer[256]:BYTE
	.if iMsg==WM_INITDIALOG
		invoke lstrcpy,addr buffer,addr bufferx
		lea eax,buffer
		push eax
		add eax,6
		push eax
		lea eax,bufferx ;mov eax,offset bufferx
		mov ebx,[eax+6]
		mov [eax+2],ebx
		mov word ptr [eax+6],"00"
		mov word ptr [eax+8],0
	;invoke logstat,eax
		invoke htodw,eax
		mov Attrib2,eax
		pop eax
		push eax
		invoke SendDlgItemMessage,hWin,1403,WM_SETTEXT,0,eax
		invoke SendDlgItemMessage,hWin,1403,WM_SETFONT,hFontL,1
		invoke SendDlgItemMessage,hWin,1411,WM_SETFONT,hFontL,1
		invoke SendDlgItemMessage,hWin,1410,WM_SETFONT,hFontL,1
		invoke SendDlgItemMessage,hWin,1402,WM_SETFONT,hFontL,1
		invoke SendDlgItemMessage,hWin,1415,WM_SETFONT,hFontL,1
		invoke GetDlgItem,hWin,1403 ;IDC_EDIT
		invoke SetFocus,eax
		pop esi
		invoke htodw,esi
		mov ebx,eax
		mov Attrib,eax
		bt bx,0 
		.if CARRY?
			invoke SendDlgItemMessage,hWin,1405,BM_SETCHECK,BST_CHECKED,0
		.endif			
		bt bx,1 
		.if CARRY?
			invoke SendDlgItemMessage,hWin,1406,BM_SETCHECK,BST_CHECKED,0
		.endif	
		bt bx,2 
		.if CARRY?
			invoke SendDlgItemMessage,hWin,1407,BM_SETCHECK,BST_CHECKED,0
		.endif	
		bt bx,5 
		.if CARRY?
			invoke SendDlgItemMessage,hWin,1408,BM_SETCHECK,BST_CHECKED,0
		.endif	
		bt bx,6 
		.if CARRY?
			invoke SendDlgItemMessage,hWin,1409,BM_SETCHECK,BST_CHECKED,0
		.endif	
		pop ebx ;esi
		mov byte ptr [ebx+2],0
		invoke SendDlgItemMessage,hWin,1411,WM_SETTEXT,0,ebx ;esi
				; get filename to bufferx
				.if LeftRight==0
					mov eax,CurrentItem
					mov lvi.iItem,eax
					;mov PrevPos1,eax
					mov lvi.iSubItem,0
					mov lvi.imask,LVIF_TEXT
					mov eax,offset bufferx
					mov lvi.pszText,eax
					mov lvi.cchTextMax,256
					; get the item
					invoke SendMessage,hList1,LVM_GETITEM,0,addr lvi    ; buffer:filename
				.else	
					mov eax,CurrentItem
					mov lvi.iItem,eax
					;mov PrevPos1,eax
					mov lvi.iSubItem,0
					mov lvi.imask,LVIF_TEXT
					mov eax,offset bufferx
					mov lvi.pszText,eax
					mov lvi.cchTextMax,256
					; get the item
					invoke SendMessage,hList2,LVM_GETITEM,0,addr lvi    ; buffer:filename
				.endif	
				invoke SendDlgItemMessage,hWin,1415,WM_SETTEXT,0,addr bufferx	
	.elseif iMsg==WM_CLOSE
		invoke EndDialog,hWin,NULL
	.elseif iMsg==WM_COMMAND


		mov eax,wParam
		mov edx,eax
		shr edx,16
		.if dx==BN_CLICKED
			.if eax==1404   ;cancel
				invoke SendMessage,hWin,WM_CLOSE,NULL,NULL
;			.elseif eax==1417   ;set
;				invoke SendDlgItemMessage,hWin,1403,WM_GETTEXT,244,addr buffer
;				invoke htodw,addr buffer
;				mov Attrib,eax
			.elseif eax==1401   ;ok
				invoke SendDlgItemMessage,hWin,1403,WM_GETTEXT,244,addr buffer
				invoke htodw,addr buffer
				mov Attrib,eax
				; get filename to bufferx
				.if LeftRight==0
					mov eax,CurrentItem
					mov lvi.iItem,eax
					;mov PrevPos1,eax
					mov lvi.iSubItem,0
					mov lvi.imask,LVIF_TEXT
					mov eax,offset bufferx
					mov lvi.pszText,eax
					mov lvi.cchTextMax,256
					; get the item
					invoke SendMessage,hList1,LVM_GETITEM,0,addr lvi    ; buffer:filename
					invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr Fulldir1	; prev path
				.else	
					mov eax,CurrentItem
					mov lvi.iItem,eax
					;mov PrevPos1,eax
					mov lvi.iSubItem,0
					mov lvi.imask,LVIF_TEXT
					mov eax,offset bufferx
					mov lvi.pszText,eax
					mov lvi.cchTextMax,256
					; get the item
					invoke SendMessage,hList2,LVM_GETITEM,0,addr lvi    ; buffer:filename
					invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr Fulldir1	; prev path
				.endif	
				mov esi,offset Fulldir1
				mov al,[esi]
				.while al!="/"	;step to first "/" = cut leading "P2k:"
					inc esi
					mov al,[esi]
				.endw
				;invoke lstrcat,esi,addr bufferx
				invoke lstrcpy,addr buffer,esi
				invoke lstrcat,addr buffer,addr bufferx
				lea esi,buffer
		;invoke logstat,esi
				push esi ; save filename
				push Attrib
				push esi
				call FSAC_open
				call FSAC_close	
				pop esi ; get saved filename
				invoke SmartRefreshAttr,esi
				invoke EndDialog,hWin,NULL
			.elseif eax==1405 ;bit 0
				mov eax,Attrib
				xor eax,1	
			.elseif eax==1406 ;bit 1
				mov eax,Attrib
				xor eax,2	
			.elseif eax==1407 ;bit 2
				mov eax,Attrib
				xor eax,4	
			.elseif eax==1408 ;bit 5
				mov eax,Attrib
				xor eax,20h	
			.elseif eax==1409 ;bit 6
				mov eax,Attrib
				xor eax,40h	
			.endif
			mov Attrib,eax
			invoke dw2hex,eax,addr bufferx
			invoke SendDlgItemMessage,hWin,1403,WM_SETTEXT,0,addr bufferx+4
		.endif
	.else
		mov eax,FALSE
		ret
	.endif
	mov  eax,TRUE
	ret
AttrProc endp
DlgF7Proc PROC uses edx hWin:HWND,iMsg:DWORD,wParam:WPARAM, lParam:LPARAM
	.if iMsg==WM_INITDIALOG
		invoke GetDlgItem,hWin,1103 ;IDC_EDIT
		invoke SetFocus,eax
	.elseif iMsg==WM_CLOSE
		invoke EndDialog,hWin,NULL
	.elseif iMsg==WM_COMMAND
		mov eax,wParam
		mov edx,eax
		shr edx,16
		.if dx==BN_CLICKED
			.if eax==1104   ;cancel
				invoke SendMessage,hWin,WM_CLOSE,NULL,NULL
			.elseif eax==1101   ;ok
				invoke GetDlgItemText,hWin,1103,ADDR bufferx,255
				invoke EndDialog,hWin,NULL
			.endif
		.endif
	.else
		mov eax,FALSE
		ret
	.endif
	mov  eax,TRUE
	ret
DlgF7Proc endp
DlgF5Proc PROC uses edx hWin:HWND,iMsg:DWORD,wParam:WPARAM, lParam:LPARAM
;
; bufferx: from path
; DestDir: to path, this would be modified
;
	.if iMsg==WM_INITDIALOG
		invoke GetDlgItem,hWin,1302 ;IDC_EDIT
		invoke SetFocus,eax
		invoke SendDlgItemMessage,hWin,1306,WM_SETTEXT,0,addr bufferx
		invoke SendDlgItemMessage,hWin,1302,WM_SETTEXT,0,addr DestDir
	.elseif iMsg==WM_CLOSE
		invoke EndDialog,hWin,NULL
	.elseif iMsg==WM_COMMAND
		mov eax,wParam
		mov edx,eax
		shr edx,16
		.if dx==BN_CLICKED
			.if eax==1304   ;cancel
				invoke SendMessage,hWin,WM_CLOSE,NULL,NULL
			.elseif eax==1303   ;ok
				invoke GetDlgItemText,hWin,1302,ADDR DestDir,255
				invoke EndDialog,hWin,NULL
			.endif
		.endif
	.else
		mov eax,FALSE
		ret
	.endif
	mov  eax,TRUE
	ret
DlgF5Proc endp
USBProc PROC uses edx hWin:HWND,iMsg:DWORD,wParam:WPARAM, lParam:LPARAM
LOCAL USBCMD:DWORD
	.if iMsg==WM_INITDIALOG
		invoke GetDlgItem,hWin,1906
		invoke SetFocus,eax
		push hInstance
		pop  ofn.hInstance
		mov  ofn.lpstrFilter, OFFSET FilterString2
		mov  ofn.lpstrFile, OFFSET bufferx
		mov  ofn.nMaxFile,255
		mov ofn.lStructSize,SIZEOF ofn
		mov ofn.lpstrDefExt,offset Defextpayload
		invoke lstrcpy,addr bufferx,StrAddr ("e398_getvolumes.usbpayload")
;		mov eax,Dev_Name_Ptr
;		add eax,4
;		invoke SendDlgItemMessage,hWin,1913,WM_SETTEXT,0,eax
		invoke dwtoa,InterfaceIndex,addr bufferx
		invoke SendDlgItemMessage,hWin,1904,WM_SETTEXT,0,addr bufferx
		;mov eax,InterfaceIndex
		;mov edi,offset SetupPacket
        ;mov     word ptr [edi+04h],ax ;8 ; Interface
	.elseif iMsg==WM_CLOSE
		invoke EndDialog,hWin,NULL
	.elseif iMsg==WM_COMMAND
		mov eax,wParam
		mov edx,eax
		shr edx,16
		.if dx==BN_CLICKED
			.if eax==1905   ;send
				invoke SendDlgItemMessage,hWin,1906,WM_GETTEXT,10,addr bufferx
				invoke htodw,addr bufferx
				mov USBCMD,eax
				invoke SendDlgItemMessage,hWin,1910,WM_GETTEXT,10,addr bufferx
				invoke htodw,addr bufferx
				push eax
				push offset seem_data ;rec buffer
				.if isPayload==0
					push 2
					lea eax,USBCMD
					push eax
				.else ; payload present
					push nBytes ;19h ;24
					mov esi,offset seem_data ;SetupPacket
					push esi
				.endif		
				call USB_Test
				.if eax==0	
					.if isPayload==0
						mov ecx,dword ptr seem_data
					.else 
						mov ecx,5	
					.endif
					inc ecx
					mov esi,offset seem_data ;buf addr
					shr ecx,2  ;/4
					mov edi,offset str_buf
	uc1loop:			mov eax,[esi]
					xchg al,ah
					rol eax,16
					xchg al,ah
					pusha	
					invoke dw2ah,eax,edi
					popa
					.if al==0
						mov al,20h
					.elseif ah==0
						mov ah,20h	
					.endif
					rol eax,16
					.if al==0
						mov al,20h
					.elseif ah==0
						mov ah,20h	
					.endif
					mov [esi],eax
					add edi,8
					add esi,4
					loop uc1loop
					invoke logstat,offset str_buf
					invoke SendDlgItemMessage,hWin,1901,LB_ADDSTRING,0,offset str_buf			
					invoke SendDlgItemMessage,hWin,1901,LB_SETCURSEL,eax,0
					.if isPayload==0
						invoke logstat,offset seem_data+4
						invoke SendDlgItemMessage,hWin,1901,LB_ADDSTRING,0,offset seem_data+4			
						invoke SendDlgItemMessage,hWin,1901,LB_SETCURSEL,eax,0
					.endif
				.endif		
			.elseif eax==1907
				xor isPayload,1
			.elseif eax==1909 ; load payload file
				invoke GetOpenFileName,addr ofn
				invoke CreateFile,offset bufferx,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
				.if eax!=INVALID_HANDLE_VALUE
					mov	hSaveFile,eax
					invoke GetFileSize,hSaveFile,addr nBytes
		    		; and compare
		    		mov nBytes,eax
					; load file into seem_data, size=seem_read_bytes
					invoke ReadFile,hSaveFile,offset seem_data,nBytes,addr nBytes,FALSE
					mov eax,nBytes
					invoke CloseHandle,hSaveFile
					invoke SendDlgItemMessage,hWin,1912,WM_SETTEXT,0,addr bufferx
				.endif	
			.endif
		.endif
	.else
		mov eax,FALSE
		ret
	.endif
	mov  eax,TRUE
	ret
USBProc endp
SeemProc PROC uses edx ecx hWin:HWND,iMsg:DWORD,wParam:WPARAM, lParam:LPARAM
	.if iMsg==WM_INITDIALOG
		invoke GetDlgItem,hWin,1801
		invoke SetFocus,eax
		push hInstance
		pop  ofn.hInstance
		mov  ofn.lpstrFilter, OFFSET FilterString
		mov  ofn.lpstrFile, OFFSET bufferx
		mov  ofn.nMaxFile,255
		mov ofn.lStructSize,SIZEOF ofn
		mov ofn.lpstrDefExt,offset Defextseem
	.elseif iMsg==WM_CLOSE
		invoke EndDialog,hWin,NULL
	.elseif iMsg==WM_COMMAND
		mov eax,wParam
		mov edx,eax
		shr edx,16
		.if dx==BN_CLICKED
			.if eax==1805 ; read
				; get seem num
				invoke SendDlgItemMessage,hWin,1801,WM_GETTEXT,255,addr buffery
				invoke htodw,addr buffery
				mov seem_num,ax
				invoke lstrcpy,addr bufferx,addr buffery
				invoke lstrcat,addr bufferx,StrAddr ("_")
				invoke SendDlgItemMessage,hWin,1802,WM_GETTEXT,255,addr buffery
				invoke lstrcat,addr bufferx,addr buffery
				invoke htodw,addr buffery
				mov seem_rec,ax
	            push    offset seem_data
	            push    0
		        push    0
			    push    eax ;seem_rec
			    mov ax,seem_num
	    		push    eax ;seem_num
	    		invoke Cmd_RDELEM
	    		nop
				.if eax!=-1
					; save to file size=seem_read_bytes-1, buffer=seem_data+1
					invoke GetSaveFileName,addr ofn
					invoke DeleteFile,offset bufferx ;savename
					invoke CreateFile,offset bufferx,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0
					mov hSaveFile,eax
					invoke SetFilePointer,hSaveFile,0,0,FILE_BEGIN
					mov eax,offset seem_data
					inc eax
					mov ecx,seem_read_bytes
					dec ecx
					invoke WriteFile,hSaveFile,eax,ecx,addr writtenb,0
					invoke CloseHandle,hSaveFile
					invoke EndDialog,hWin,NULL
				.endif
			.elseif eax==1806   ;write
				; get seem num
				invoke SendDlgItemMessage,hWin,1801,WM_GETTEXT,255,addr buffery
				invoke htodw,addr buffery
				mov seem_num,ax
				mov seem_no,eax
				invoke lstrcpy,addr bufferx,addr buffery
				invoke lstrcat,addr bufferx,StrAddr ("_")
				invoke SendDlgItemMessage,hWin,1802,WM_GETTEXT,255,addr buffery
				invoke lstrcat,addr bufferx,addr buffery
				invoke htodw,addr buffery
				; get size
				mov seem_rec,ax
				mov rec_no,eax
	            push    offset seem_data
	            push    0
		        push    0
			    push    eax ;seem_rec
			    mov ax,seem_num
	    		push    eax ;seem_num
	    		invoke Cmd_RDELEM
	    		dec     seem_read_bytes
	    		;mov eax,seem_read_bytes
	    		; get filesize
				invoke GetOpenFileName,addr ofn
				invoke CreateFile,offset bufferx,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
				.if eax!=INVALID_HANDLE_VALUE
					mov	hSaveFile,eax
					invoke GetFileSize,hSaveFile,addr nBytes
		    		; and compare
		    		mov nBytes,eax
					; load file into seem_data, size=seem_read_bytes
					invoke ReadFile,hSaveFile,offset seem_data2,nBytes,addr nBytes,FALSE
					mov eax,nBytes
					invoke CloseHandle,hSaveFile
					push offset seem_data2
		            push    seem_read_bytes ;bytes=filesize
			        push    0
				    push  rec_no
		    		push  seem_no
		    		;invoke Cmd_STELEM ; call
		    		call Seem_Write
					;invoke CloseHandle,hSaveFile
		    	.endif	
				invoke EndDialog,hWin,NULL
			.endif
		.endif
	.else
		mov eax,FALSE
		ret
	.endif
	mov  eax,TRUE
	ret
SeemProc endp
;DisplaySeem proc hWin:DWORD,Seemnum:DWORD,Seemrec:DWORD,Seemoffs:DWORD,Seembit:DWORD
;			;ret
;				.if _DevIF!=0
;					invoke GetSeemBit,Seemnum,Seemrec,Seemoffs,Seembit
;;			        push    offset bufferx
;;	                mov eax,Seemoffs
;;	                inc eax
;;	                push eax
;;	                push    0
;;	                push    Seemrec
;;	                push    Seemnum
;;	                invoke Cmd_RDELEM
;;	                mov eax,seem_read_bytes
;;	                mov esi,offset bufferx
;;	                add esi,Seemoffs
;;	                inc esi
;;	                mov eax,0
;;	                mov al,[esi]
;;	                push eax
;;	                invoke dw2hex,eax,addr bufferx
;;	                invoke SendDlgItemMessage,hWin,1867,WM_SETTEXT,0,addr bufferx+6
;;					; display bit
;;					mov esi,offset Bittable1
;;					add esi,Seembit
;;	                pop eax
;;					and al,[esi]
;					.if al==0
;						invoke SendDlgItemMessage,hWin,1863,BM_SETCHECK,BST_UNCHECKED,0
;					.else	
;						invoke SendDlgItemMessage,hWin,1863,BM_SETCHECK,BST_CHECKED,0
;					.endif 
;				.endif	
;				ret
;DisplaySeem endp
ToggleListSeemItem proc
LOCAL lvi:LV_ITEM
LOCAL buffer[256]:BYTE
LOCAL Seemnum:DWORD
LOCAL Seemrec:DWORD
LOCAL Seemoffs:DWORD
LOCAL Seembit:DWORD
LOCAL Dash:BYTE
			invoke SendMessage,hListSeem,LVM_GETNEXTITEM,-1,LVNI_FOCUSED
			mov lvi.iItem,eax
			mov lvi.iSubItem,1 ;seemnum
			mov lvi.imask,LVIF_TEXT
			lea eax,buffer
			mov lvi.pszText,eax
			mov lvi.cchTextMax,256
			; get the item
			invoke SendMessage,hListSeem,LVM_GETITEM,0,addr lvi    ; buffer:filename
			invoke htodw,lvi.pszText
			mov Seemnum,eax
			inc lvi.iSubItem
			invoke SendMessage,hListSeem,LVM_GETITEM,0,addr lvi    ; buffer:filename
			invoke htodw,lvi.pszText
			mov Seemrec,eax
			inc lvi.iSubItem
			invoke SendMessage,hListSeem,LVM_GETITEM,0,addr lvi    ; buffer:filename
			mov esi,lvi.pszText
			mov al,[esi]
			mov Dash,al
			invoke htodw,lvi.pszText
			mov Seemoffs,eax
			inc lvi.iSubItem
			invoke SendMessage,hListSeem,LVM_GETITEM,0,addr lvi    ; buffer:filename
			invoke htodw,lvi.pszText
			mov Seembit,eax
			.if Dash!="-" && _DevIF!=0
				invoke ToggleSeemBit,Seemnum,Seemrec,Seemoffs,Seembit
				; refresh display
				invoke GetSeemBit,Seemnum,Seemrec,Seemoffs,Seembit
			    mov lvi.imask, LVIF_IMAGE
				mov lvi.iSubItem,0
				.if eax==0
				    mov     lvi.iImage, 1
				.else	
				    mov     lvi.iImage, 2
				.endif
				invoke SendMessage,hListSeem, LVM_SETITEM,0, addr lvi
			.endif	
			ret
ToggleListSeemItem endp
;SetSeemByte proc
;LOCAL lvi:LV_ITEM
;LOCAL buffer[256]:BYTE
;LOCAL Seemnum:DWORD
;LOCAL Seemrec:DWORD
;LOCAL Seemoffs:DWORD
;LOCAL Seembit:DWORD
;
;			invoke SendMessage,hListSeem,LVM_GETNEXTITEM,-1,LVNI_FOCUSED
;			mov lvi.iItem,eax
;			mov lvi.iSubItem,1 ;seemnum
;			mov lvi.imask,LVIF_TEXT
;			lea eax,buffer
;			mov lvi.pszText,eax
;			mov lvi.cchTextMax,256
;			; get the item
;			invoke SendMessage,hListSeem,LVM_GETITEM,0,addr lvi    ; buffer:filename
;			invoke htodw,lvi.pszText
;			mov Seemnum,eax
;			inc lvi.iSubItem
;			invoke SendMessage,hListSeem,LVM_GETITEM,0,addr lvi    ; buffer:filename
;			invoke htodw,lvi.pszText
;			mov Seemrec,eax
;			inc lvi.iSubItem
;			invoke SendMessage,hListSeem,LVM_GETITEM,0,addr lvi    ; buffer:filename
;			invoke htodw,lvi.pszText
;			mov Seemoffs,eax
;			.if Seemoffs!=0D1h && _DevIF!=0
;
;
;
;				; refresh display
;				invoke GetSeemBit,Seemnum,Seemrec,Seemoffs,Seembit
;			    mov lvi.imask, LVIF_IMAGE
;				mov lvi.iSubItem,0
;				.if eax==0
;				    mov     lvi.iImage, 1
;				.else	
;				    mov     lvi.iImage, 2
;				.endif
;				invoke SendMessage,hListSeem, LVM_SETITEM,0, addr lvi
;			.endif	
;			ret
;SetSeemByte endp
SeemFuncProc PROC uses edx ecx hWin:HWND,iMsg:DWORD,wParam:WPARAM, lParam:LPARAM
LOCAL Seemnum:DWORD
LOCAL Seemrec:DWORD
LOCAL Seemoffs:DWORD
LOCAL Seembit:DWORD
LOCAL ti:TOOLINFO
LOCAL LVCount:DWORD
LOCAL CurrPos:DWORD
	.if iMsg==WM_INITDIALOG
		mov FirstSeem,0
		invoke ReadFunctions,hWin
;		.if _DevIF!=0
;			invoke ReadFunctionSeems
;			invoke SetCheckmarks
;		.endif	
		; menu
		invoke CreateMenu
		mov hSMenu,eax
		invoke CreatePopupMenu
		mov hSPMenu,eax
		invoke AppendMenu,hSMenu,MF_POPUP OR MF_STRING,hSPMenu,StrAddr("Seem")
		invoke AppendMenu,hSPMenu,MF_STRING,11003,StrAddr("Toggle Seem Bit")
		invoke AppendMenu,hSPMenu,MF_STRING,11001,StrAddr("Write Seems to the phone.")
		invoke AppendMenu,hSPMenu,MF_STRING,11002,StrAddr("Discard all changes.")
		;
		invoke GetDlgItem,hWin,1864
		mov hWrite,eax
		invoke GetDlgItem,hWin,1867
		mov hSeemByte,eax
		invoke GetDlgItem,hWin,1863
		mov hBitCheckmark,eax
		invoke GetDlgItem,hWin,1867
		mov hByteBox,eax
		invoke GetDlgItem,hWin,1868
		mov hDiscard,eax
		mov ButtImList1.margin.left,16
		mov ButtImList6.margin.left,16	
		mov ButtImList8.margin.left,16	
		mov ButtImList9.margin.left,16	
		invoke SendDlgItemMessage,hWin,1853,BCM_SETIMAGELIST,0,addr ButtImList1
		invoke SendDlgItemMessage,hWin,1864,BCM_SETIMAGELIST,0,addr ButtImList8
		invoke SendDlgItemMessage,hWin,1865,BCM_SETIMAGELIST,0,addr ButtImList6
		invoke SendDlgItemMessage,hWin,1868,BCM_SETIMAGELIST,0,addr ButtImList9
		mov ButtImList1.margin.left,0	
		mov ButtImList6.margin.left,0	
		mov ButtImList8.margin.left,0	
		mov ButtImList9.margin.left,0	
		;
		;/* From Iczelions tutorial #27:What we need for a tooltip */
		invoke CreateWindowEx,NULL,ADDR ToolTipsClassName,NULL,TTS_ALWAYSTIP + TTS_BALLOON,CW_USEDEFAULT,\ 
       	CW_USEDEFAULT,CW_USEDEFAULT,CW_USEDEFAULT,NULL,NULL,hInstance,NULL 
		mov hwndTool,eax
		mov ti.cbSize,sizeof TOOLINFO
		mov ti.uFlags,TTF_SUBCLASS
		push hWin
		pop ti.hWnd
		invoke EnumChildWindows,hWin,addr EnumChild,addr ti
		mov _lvi.iItem,-1
	;
	; Needed for rightclick menu
	;	
    .ELSEIF iMsg==WM_CONTEXTMENU   ;has user right clicked mouse?
      mov eax, lParam             ;if so, show the popup menu			
      and eax, 0ffffh
      mov ebx, lParam
      shr ebx, 16
      ;add ebx,6
      mov esi,wParam
      .if esi==hListSeem
      	invoke TrackPopupMenu, hSPMenu, TPM_LEFTALIGN, eax, ebx, 0, hWin, 0
      .endif		
	.elseif iMsg==WM_CLOSE
		invoke FreeSeemMem
		invoke EndDialog,hWin,NULL
	.elseif iMsg==WM_COMMAND
		pusha
		.if _DevIF!=0
			invoke ShowWindow,hWrite,TRUE
		.else	
			invoke ShowWindow,hWrite,FALSE
		.endif
		popa
		mov eax,wParam
		mov edx,eax
		shr edx,16
		.if dx==BN_CLICKED
			.if eax==1853 ; search
				invoke SendDlgItemMessage,hWin,1852,WM_GETTEXT,255,addr buffery
				invoke szLower,addr buffery
				; loop thru LV items
				invoke SendMessage,hListSeem,LVM_GETITEMCOUNT,0,0
				mov LVCount,eax
				mov _lvi.cchTextMax,256
				mov _lvi.iSubItem,0
				mov _lvi.imask,LVIF_TEXT
				mov eax,offset bufferx
				mov _lvi.pszText,eax
				mov eax,0 ;-1
				.while eax==0 ;-1
					inc _lvi.iItem
					mov eax,LVCount
					.if eax<_lvi.iItem
						mov eax,-1
						mov _lvi.iItem,-1
						.break
					.endif
					invoke SendMessage,hListSeem,LVM_GETITEM,0,addr _lvi
					invoke lstrcpy,addr bufferz,addr bufferx
					invoke szLower,addr bufferx
;					invoke lstrlen,addr buffery	
;					mov ebx,eax
;					invoke lstrlen,addr bufferx
;					mov ecx,eax
					invoke InString,1,addr bufferx,addr buffery
					;.if eax==0
					;	mov eax,-1
					;.endif
					;invoke BinSearch,0,addr bufferx,ecx,addr buffery,ebx
				.endw
				.if eax==-1 ; not found
					invoke SendMessage,hWin,WM_SETTEXT,0,StrAddr ("Seem function not found!")
				.else	; found
					mov eax,_lvi.iItem
					mov _lvi.imask,LVIF_STATE
					mov _lvi.stateMask,LVIS_SELECTED or LVIS_FOCUSED  
					mov _lvi.state,LVIS_SELECTED or LVIS_FOCUSED  
					invoke SendMessage,hListSeem,LVM_SETITEMSTATE,eax,addr _lvi
					invoke LockWindowUpdate,hListSeem
					invoke SendMessage,hListSeem,LVM_ENSUREVISIBLE,_lvi.iItem,FALSE
					invoke LockWindowUpdate,NULL
					invoke SendMessage,hWin,WM_SETTEXT,0,addr bufferz
					mov _lvi.imask,LVIF_TEXT
				.endif	
;			.elseif eax==1869 ; textbox byte set
;				invoke SendMessage,hSeemByte,WM_GETTEXT,255,addr bufferz
;				invoke htodw,addr bufferz
;				invoke SetSeemByte
			.elseif eax==1864 ; write
				mov esi,offset SeemList
				mov edi,offset SeemAddrList
				;DbgDump esi,32
				.while dword ptr [esi]!=0
					pusha
					mov eax,[esi]
					mov ebx,eax
					and eax,0ffffh
					shr ebx,16
					; eax: rec  ebx:seem
					push eax
					push ebx
					; get size
		            push    offset seem_data
		            push    0
			        push    0
				    push    eax ;seem_rec
		    		push    ebx ;seem_num
		    		invoke Cmd_RDELEM
		    		dec     seem_read_bytes
		    		pop ebx
		    		pop eax
					; do write
					push [edi]
				;DbgDump [edi],32
		            push  seem_read_bytes ;bytes=filesize
			        push  0
				    push  eax
		    		push  ebx
		    		call Seem_Write
		    		popa
					add esi,4
					add edi,4
				.endw
				; free buffers
				invoke FreeSeemMem
				; re-read from phone
				mov FirstSeem,0
				; save curr pos in LV
				invoke SendMessage,hListSeem,LVM_GETNEXTITEM,0,LVNI_SELECTED
				mov CurrPos,eax
				invoke ReadFunctions,hWin
				; restore curr pos in LV
			.elseif eax==1868 ; discard
				; free buffers
				invoke FreeSeemMem
				; re-read from phone
				mov FirstSeem,0
				; save curr pos in LV
				invoke SendMessage,hListSeem,LVM_GETNEXTITEM,0,LVNI_SELECTED
				mov CurrPos,eax
				invoke ReadFunctions,hWin
				; restore curr pos in LV
				invoke SendMessage,hListSeem,LVM_ENSUREVISIBLE,CurrPos,FALSE
			.elseif eax==1865 ; close
				invoke FreeSeemMem
				invoke EndDialog,hWin,NULL
			.elseif eax==11003 || 1863 ; toggle bit
				invoke ToggleListSeemItem
				invoke EnableWindow,hDiscard,TRUE
				invoke EnableWindow,hWrite,TRUE
			.endif
;		.elseif dx==EN_CHANGE 
;			and eax,0ffffh
;			.if eax==1867
;				invoke SendMessage,hSeemByte,WM_GETTEXT,255,addr bufferz
;				invoke htodw,addr bufferz
;				nop
;			.endif	
		.endif
	.elseif iMsg==WM_NOTIFY
		push edi
		mov edi,lParam
		assume edi:ptr NMHDR
		mov eax,[edi].hwndFrom
		.if eax==hListSeem
			.if [edi].code==LVN_ITEMCHANGED
				assume edi:ptr NMLISTVIEW
				; get seem numbers
				mov eax,[edi].iItem
				mov _lvi.iItem,eax
				mov _lvi.iSubItem,1
				mov _lvi.imask,LVIF_TEXT
				mov eax,offset bufferx
				mov _lvi.pszText,eax
				mov _lvi.cchTextMax,256
				; get the item
				invoke SendMessage,hListSeem,LVM_GETITEM,0,addr _lvi   ; buffer:filename
				invoke SendDlgItemMessage,hWin,1855,WM_SETTEXT,0,addr bufferx
				invoke htodw,addr bufferx
				mov Seemnum,eax
				inc _lvi.iSubItem
				mov _lvi.imask,LVIF_TEXT
				invoke SendMessage,hListSeem,LVM_GETITEM,0,addr _lvi   ; buffer:filename
				invoke SendDlgItemMessage,hWin,1857,WM_SETTEXT,0,addr bufferx
				invoke htodw,addr bufferx
				mov Seemrec,eax
				inc _lvi.iSubItem
				mov _lvi.imask,LVIF_TEXT
				invoke SendMessage,hListSeem,LVM_GETITEM,0,addr _lvi   ; buffer:filename
				invoke SendDlgItemMessage,hWin,1859,WM_SETTEXT,0,addr bufferx
				mov esi,offset bufferx
				.if byte ptr [esi]=="-"
					mov Seemoffs,-1
				.else
					invoke htodw,addr bufferx
					mov Seemoffs,eax
				.endif
				inc _lvi.iSubItem
				mov _lvi.imask,LVIF_TEXT
				invoke SendMessage,hListSeem,LVM_GETITEM,0,addr _lvi   ; buffer:filename
				invoke SendDlgItemMessage,hWin,1861,WM_SETTEXT,0,addr bufferx
				invoke htodw,addr bufferx
				mov Seembit,eax
				; read seem set checkmark
				.if FirstSeem==1 && Seemoffs!=-1
					invoke ShowWindow,hBitCheckmark,SW_SHOW
					invoke ShowWindow,hByteBox,SW_SHOW
					invoke GetSeemBit,Seemnum,Seemrec,Seemoffs,Seembit
					.if eax==0
						invoke SendDlgItemMessage,hWin,1863,BM_SETCHECK,BST_UNCHECKED,0
					.else	
						invoke SendDlgItemMessage,hWin,1863,BM_SETCHECK,BST_CHECKED,0
					.endif
				.endif	
				.if Seemoffs==-1
					invoke ShowWindow,hBitCheckmark,SW_HIDE
					invoke ShowWindow,hByteBox,SW_HIDE
				.endif
				xor eax,eax
				mov al,ActualSeemByte
                invoke dw2hex,eax,addr bufferx
                invoke SendDlgItemMessage,hWin,1867,WM_SETTEXT,0,addr bufferx+6
				assume edi:ptr NMHDR
			.elseif [edi].code==NM_CUSTOMDRAW  ; coloured rows
	            assume edi:ptr NMLVCUSTOMDRAW
               .if [edi].nmcd.dwDrawStage == CDDS_PREPAINT
				  invoke SetWindowLong,hWin,DWL_MSGRESULT,CDRF_NOTIFYITEMDRAW
                  mov eax,CDRF_NOTIFYITEMDRAW
                  ret
               .elseif [edi].nmcd.dwDrawStage == CDDS_ITEMPREPAINT
    		      ;;;;;;;do stuff in this section              
				mov eax,[edi].nmcd.dwItemSpec
				mov _lvi.iItem,eax
				mov _lvi.iSubItem,3
				mov _lvi.imask,LVIF_TEXT
				mov eax,offset bufferx
				mov _lvi.pszText,eax
				mov _lvi.cchTextMax,256
				; get the item
				invoke SendMessage,hListSeem,LVM_GETITEM,0,addr _lvi   ; buffer:filename
				mov esi,offset bufferx
                  .if byte ptr [esi]=="-"
			           MOV [EDI].clrText,00ffh   	; red text
			           MOV [EDI].clrTextBk,0ffffh   ; yellow text background
			           ;invoke ShowWindow,hBitCheckmark,SW_HIDE
			           ;invoke EnableWindow,hBitCheckmark,FALSE
			      .else     
			           ;invoke ShowWindow,hBitCheckmark,SW_SHOW
			           ;invoke EnableWindow,hBitCheckmark,TRUE
                  .endif
            	  ;;;;;;;stop doing crap
			      assume edi:ptr NMHDR
				  invoke SetWindowLong,hWin,DWL_MSGRESULT,CDRF_NEWFONT                  
                  mov eax, CDRF_NEWFONT
                  ret
               .endif
			.elseif [edi].code==LVN_ITEMACTIVATE  ; doubleclick, enter
				invoke ToggleListSeemItem
				invoke EnableWindow,hDiscard,TRUE
				invoke EnableWindow,hWrite,TRUE
			.endif
;		.elseif eax==1867 ;hSeemByte
;			nop
		.endif
		assume edi:NOTHING
		pop edi
	.else
		mov eax,FALSE
		ret
	.endif
	mov  eax,TRUE
	ret
SeemFuncProc endp
BatchProc PROC uses edi esi edx ebx hWin:HWND,iMsg:DWORD,wParam:WPARAM, lParam:LPARAM
LOCAL	hFile:DWORD
LOCAL	hMemConfig:DWORD
LOCAL   nConfigCount:DWORD
LOCAL lvc:LV_COLUMN
LOCAL seemnum:dword
LOCAL seemrec:dword
LOCAL seemoffs:dword
LOCAL seembit:dword
 
	.if iMsg==WM_INITDIALOG
		invoke ShowWindow,hSplash,SW_HIDE
		invoke GetDlgItem,hWin,1601 ;IDC_EDIT
		invoke SetFocus,eax
		invoke SendDlgItemMessage,hWin,1603,LB_ADDSTRING,0,addr bufferx
		invoke SendDlgItemMessage,hWin,1603,LB_ADDSTRING,0,addr Sep
		invoke lstrcpy,addr bufferh,addr bufferx
				;
				; start thread
				;
				mov ThreadStarted,1
				mov startInfo.dwFlags,STARTF_USESHOWWINDOW
				mov startInfo.wShowWindow,SW_HIDE
				invoke CreateProcess,NULL,addr CmdDelIp,NULL,NULL,FALSE,\ 
		              NORMAL_PRIORITY_CLASS,\ 
		              NULL,NULL,ADDR startInfo,ADDR processInfo
				mov startInfo.wShowWindow,SW_SHOW
				mov startInfo.dwFlags,STARTF_USESHOWWINDOW
				mov startInfo.wShowWindow,SW_HIDE
				invoke CreateProcess,NULL,addr CmdInsFtpDrive,NULL,NULL,FALSE,\ 
		              NORMAL_PRIORITY_CLASS,\ 
		              NULL,NULL,ADDR startInfo,ADDR processInfo
				mov startInfo.wShowWindow,SW_SHOW
				mov fromThread,0
				mov fromThread2,0
				.if isUSBLAN==0
					invoke FindUSBClass
	                push    offset Thread_ID
	                push    0
	                push    0
	                push    offset CheckP2kStatusThread
	                push    0
	                push    0
	                call    CreateThread
	            .else
					invoke FindUSBLAN
	                push    offset Thread_ID
	                push    0
	                push    0
	                push    offset CheckUSBLANStatusThread
	                push    0
	                push    0
	                call    CreateThread
	            .endif	    
		invoke lstrcpy,addr bufferx,addr bufferh
		.if isUSBLAN==3 && _DevIF==0
			invoke SendDlgItemMessage,hWin,1603,LB_ADDSTRING,0,StrAddr("Please wait until connection established.(Phone beeps.)")
			invoke SendDlgItemMessage,hWin,1603,LB_ADDSTRING,0,addr Sep
		.endif	
		invoke CreateFile,offset bufferx,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
		.if eax!=INVALID_HANDLE_VALUE
			mov	hFile,eax
			invoke GetFileSize,hFile,addr nBytes
			inc	eax
			mov	nBytes,eax
			invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
			mov	hMemConfig,eax
			invoke ReadFile,hFile,hMemConfig,nBytes,addr nBytes,FALSE
			invoke CloseHandle,hFile
		.endif
		mov	nConfigCount,0
		mov	esi,hMemConfig
		.if esi
			mov	edi,esi
		  Nx:
			mov	al,[esi]
			cmp	al,0Dh
			je @f
			mov	[edi],al
			inc	esi
			inc	edi
			or al,al
			je Ex
			jmp	Nx
		  @@:
			inc	nConfigCount
			mov	al,0
			mov	[edi],al
			inc	edi
			add	esi,2
			mov	al,[esi]
			or al,al
			jne	Nx
		  Ex:
			mov	[edi],al
			xor	eax,eax
		.endif
			mov	eax,nConfigCount
			.if eax
				;Allocate memory for word pointers
				lea	eax,[eax*4+4]
				invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
				mov	hMemConfigPtrs,eax
				mov	esi,hMemConfig
				mov	edi,hMemConfigPtrs
				;Setup word pointers
				.while byte ptr [esi]
					mov	[edi],esi
					add	edi,4
					.while byte ptr [esi]
						inc	esi
					.endw
					inc	esi
				.endw
			.endif
		mov	edx,hMemConfigPtrs
		.while dword ptr [edx]
			; check automode
			;mov esi,[edx]
			;.if word ptr [esi]=="ua"
			;	mov BatchAuto,1
			;.endif 
			push edx
			invoke SendDlgItemMessage,hWin,1603,LB_ADDSTRING,0,[edx]
			pop	edx
			add	edx,4
		.endw
		invoke GlobalFree,hMemConfig
		invoke GlobalFree,hMemConfigPtrs
;		.if BatchAuto==1
;			invoke SendMessage,hWin,WM_COMMAND,1601,0
;		.endif
	.elseif iMsg==WM_CLOSE
		invoke EndDialog,hWin,NULL
	.elseif iMsg==WM_COMMAND
		mov eax,wParam
		mov edx,eax
		shr edx,16
		.if dx==BN_CLICKED
			.if eax==1602   ;cancel
				mov DevFound,999
				invoke SendMessage,hWin,WM_CLOSE,NULL,NULL
			.elseif eax==1601   ;ok, execute
				invoke SendDlgItemMessage,hWin,1603,LB_GETCOUNT,0,0
				mov isBatch,1
				push P2kLimit
				mov P2kLimit,3
;				.if isUSBLAN==3
;					call DevMonitor_ProcLAN
;				.else	
;					call DevMonitor_Proc
;				.endif	
				.if _DevIF==1 ;DevFound==1
					;push eax
					;invoke GetVolInfo
;					.if _DevIF!=0
;						mov lvc.imask,LVCF_TEXT				
;						invoke GetMsgAddr,45
;						mov lvc.pszText,eax ;offset Heading3
;						invoke SendMessage,hList2,LVM_SETCOLUMN,2,addr lvc
;						invoke lstrcpy,addr bufferx,addr	szP2kDev  ; "P2k:"
;						invoke lstrcat,addr bufferx,addr	P2kDirectory2 ; + actual dir name
;						invoke SendMessage,hHead2,WM_SETTEXT,0,addr bufferx ;szP2kDev
;						mov Drive2,0
;						invoke SendMessage,hLB2,CB_SETCURSEL,0,0	
;						invoke P2kGetFileList2,hWin
;					.endif
					invoke SendDlgItemMessage,hWin,1603,LB_GETCOUNT,0,0	
					mov nConfigCount,eax
					mov eax,2
					.while eax!=nConfigCount
						push eax
						invoke SendDlgItemMessage,hWin,1603,LB_GETTEXT,eax,addr bufferx
						mov esi,offset bufferx
						mov ax,[esi]
						mov bl,[esi+2]
						add  esi,3
						mov W2Kesi,esi
						;
						; copy-read
						;
						.if bl==" " && ax=="pc"   	
							invoke GetCL,1,addr buffery  ;get launchdir
							mov edi,offset buffery
							invoke lstrlen,addr buffery
							add edi,eax

							.while byte ptr [edi]!="\"
								dec edi
							.endw
							inc edi
							mov byte ptr [edi],0
							invoke lstrcat,addr buffery,[W2Kesi] ;esi
							invoke logstat,addr buffery
							;					
							; read file
							;
							invoke CreateFile,addr buffery,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
							mov	hReadFile,eax
							invoke GetFileSize,hReadFile,addr nBytes
							inc	eax
							mov	nBytes,eax
							invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
							mov	hMemFile,eax
							invoke ReadFile,hReadFile,hMemFile,nBytes,addr nBytes,FALSE
							invoke CloseHandle,hReadFile
						;
						; copy-write
						;
						.elseif bl==" " && ax=="ot" && hReadFile!=INVALID_HANDLE_VALUE   	; copy-write
	;						invoke lstrcpy,addr buffery,addr szSkinPath
	;						invoke lstrcat,addr buffery,esi
	;						mov edi,offset buffery
	;						invoke lstrlen,addr buffery
	;						add edi,eax
	;						.while byte ptr [edi]!="\"
	;							dec edi
	;						.endw
	;						mov byte ptr [edi],"/"
							;invoke ShowWindow,hList1,SW_HIDE
							;invoke ShowWindow,hList2,SW_HIDE
							invoke logstat,[W2Kesi] ;esi ;addr buffery
						;	push [W2Kesi] ;esi ;offset buffery ;esi ; save name
						;---
							push [W2Kesi]
							pop NameHW
							invoke CreateThread,0,0,addr P2kUploadHW,0,0,0
							invoke DialogBoxParam,hInstance, 1700,hWin,OFFSET WaitProc,NULL
;							push 4  	;attrib
;							push [W2Kesi] ;esi ;offset buffery ;esi 	;name
;							invoke FSAC_open
;							
;							mov eax,nBytes
;							mov edx,0
;							mov ebx,1000
;							div ebx
;							inc eax
;							shl eax,16 ; to upper dword
;							invoke SendMessage,hBar,PBM_SETRANGE,0,eax
;							invoke SendMessage,hBar,PBM_SETSTEP,1,0
;							invoke SendMessage,hBar,PBM_SETPOS,0,0
;							
;							push nBytes ;filesize
;							push hMemFile ; ptr to file in mem
;							invoke FSAC_write
;							invoke FSAC_close  ; upload now works!
						;---	
							;invoke SendDlgItemMessage,hWin,1012,WM_SETFONT,hFontL,TRUE
							invoke GlobalFree,hMemFile
							invoke UpdateStatusBar
							
						;	pop esi ;recover saved name
							invoke SmartRefreshCopy,[W2Kesi],nBytes,07000400h
						;
						; make directory
						;
						.elseif bl==" " && ax=="dm" ; makedir
						;	push esi
							invoke logstat,[W2Kesi] ;esi
							push 4h ;04000000h
							push [W2Kesi] ;esi
							call FSAC_makedir
						;	pop esi
							invoke lstrcat,[W2Kesi],addr szSlash
							invoke lstrcat,[W2Kesi],addr EmptyDirMark
						;	push esi ;save name
							push 4  	;attrib
							push [W2Kesi] ;esi	;name
							invoke FSAC_open
							push 1  ;filesize
							push offset EmptyDirMarks5vi  ; ptr to file in mem
							invoke FSAC_write
							invoke FSAC_close  
							invoke UpdateStatusBar
						;	pop esi ;recover saved name
							invoke SmartRefreshCopy,[W2Kesi],1,07000400h
						;
						; del directory
						;
						.elseif bl==" " && ax=="dr" ; delete
						;	invoke lstrcat,esi,addr bufferx
                			invoke GetMsgAddr,33
							invoke logstat,eax ;addr str_deleting
							invoke logstat,[W2Kesi] ;esi
						;	push esi ; save filename
							push 4
							push [W2Kesi] ;esi
							call FSAC_deldir
						;	pop esi ; get saved filename
							invoke SmartRefreshDelDir,[W2Kesi] ;esi
							invoke UpdateStatusBar
						;
						; del file
						;
						.elseif bl==" " && ax=="mr" ; delete
						;	invoke lstrcat,esi,addr bufferx
			                invoke GetMsgAddr,33
							invoke logstat,eax ;addr str_deleting
							invoke logstat,[W2Kesi] ;esi
						;	push esi ; save filename
							push [W2Kesi] ;esi
							call FSAC_delete ; delete works!!!!
						;	pop esi ; get saved filename
							invoke SmartRefreshDelDir,[W2Kesi] ;esi
							invoke UpdateStatusBar
						;
						; read in attrib
						;
						.elseif bl==" " && ax=="ta" ; get attrib
							invoke atodw,[W2Kesi] ;esi
							mov Attrib,eax
						;
						; set file attrib
						;
						.elseif bl==" " && ax=="as" ; set attrib
							;push esi ; save filename
							push Attrib
							push [W2Kesi] ;esi
							call FSAC_open
							call FSAC_close	
							;pop ebx ; get saved filename


							invoke SmartRefreshAttr,[W2Kesi] ;ebx
							invoke UpdateStatusBar
						;
						; external cmd
						;
						.elseif bl==" " && ax=="##" ; ext cmd
							invoke GetCL,1,addr buffery  ;get launchdir
							mov edi,offset buffery
							invoke lstrlen,addr buffery
							add edi,eax
							.while byte ptr [edi]!="\"
								dec edi
							.endw
							inc edi
							mov byte ptr [edi],0
							invoke SetCurrentDirectory,addr buffery
							invoke lstrcpy,addr buffery,StrAddr(" /c ")
							invoke lstrcat,addr buffery,[W2Kesi]
							invoke ShellExecute,hWin,NULL,StrAddr("cmd.exe"),addr buffery,0,SW_SHOW
						;
						; 
						;
						.elseif bl==" " && ax=="ss" ; setseem bit ss 0032 0001 00db 2
							mov esi,[W2Kesi]
							mov byte ptr [esi+4],0
							mov byte ptr [esi+9],0
							mov byte ptr [esi+14],0
							; get numbers
							invoke htodw,esi
							mov seemnum,eax
							add esi,5
							invoke htodw,esi
							mov seemrec,eax
							add esi,5
							invoke htodw,esi
							;inc eax
							mov seemoffs,eax
							add esi,5
							invoke htodw,esi
							mov seembit,eax
							; read seem to seem_data
					        push offset bufferx
				            mov eax,seemoffs
				            inc eax
				            push eax
				            push 0
				            push seemrec
				            push seemnum
				            invoke Cmd_RDELEM
							; set bit
							mov esi,offset Bittable1
							add esi,seembit
							mov bl,[esi]
							mov edi,offset bufferx
							add edi,seemoffs
							mov al,[edi]
							or al,[esi]
							mov [edi],al
							; write seem
					        push offset bufferx
				            mov eax,seemoffs
				            inc eax
				            push eax
				            push 0
				            push seemrec
				            push seemnum
				            invoke Seem_Write ;Cmd_STELEM
						.elseif bl==" " && ax=="sr" ; resetseem bit sr 0032 0001 00db 2
							mov esi,[W2Kesi]
							mov byte ptr [esi+4],0
							mov byte ptr [esi+9],0
							mov byte ptr [esi+14],0
							; get numbers
							invoke htodw,esi
							mov seemnum,eax
							add esi,5
							invoke htodw,esi
							mov seemrec,eax
							add esi,5
							invoke htodw,esi
							;inc eax

							mov seemoffs,eax
							add esi,5
							invoke htodw,esi
							mov seembit,eax
							; read seem to seem_data
					        push offset bufferx
				            mov eax,seemoffs
				            inc eax
				            push eax
				            push 0
				            push seemrec
				            push seemnum
				            invoke Cmd_RDELEM
				            ; reset bit
							mov esi,offset Bittable2
							add esi,seembit
							mov bl,[esi]
							mov edi,offset bufferx
							add edi,seemoffs
							mov al,[edi]
							and al,[esi]
							mov [edi],al
							; write seem
					        push offset bufferx
				            mov eax,seemoffs
				            inc eax
				            push eax
				            push 0
				            push seemrec
				            push seemnum
				            invoke Seem_Write ;Cmd_STELEM
						.elseif bl==" " && ax=="st" ; toggleseem bit sr 0032 0001 00db 2
							mov esi,[W2Kesi]
							mov byte ptr [esi+4],0
							mov byte ptr [esi+9],0
							mov byte ptr [esi+14],0
							; get numbers
							invoke htodw,esi
							mov seemnum,eax
							add esi,5
							invoke htodw,esi
							mov seemrec,eax
							add esi,5
							invoke htodw,esi
							;inc eax
							mov seemoffs,eax
							add esi,5
							invoke htodw,esi
							mov seembit,eax
							; read seem to seem_data
					        push offset bufferx
				            mov eax,seemoffs
				            inc eax
				            push eax
				            push 0
				            push seemrec
				            push seemnum
				            invoke Cmd_RDELEM
				            ; reset bit
							mov esi,offset Bittable1
							add esi,seembit
							mov bl,[esi]
							mov edi,offset bufferx
							add edi,seemoffs
							mov al,[edi]
							xor al,[esi]
							mov [edi],al
							; write seem
					        push offset bufferx
				            mov eax,seemoffs
				            inc eax
				            push eax
				            push 0
				            push seemrec
				            push seemnum
				            invoke Seem_Write ;Cmd_STELEM
						.elseif bl==" " && ax=="sd" ; download seem: sd 0032 0001
							mov esi,[W2Kesi]
							invoke lstrcpy,addr buffery,esi
							mov byte ptr [esi+4],0
							mov byte ptr [esi+9],0
							; get numbers
							invoke htodw,esi
							mov seemnum,eax
							add esi,5
							invoke htodw,esi
							mov seemrec,eax
							; read seem to seem_data
					        push offset bufferx
				            push 0
				            push 0
				            push seemrec
				            push seemnum
				            invoke Cmd_RDELEM
				            ; write to file
							mov esi,offset buffery
							mov byte ptr [esi+4],"_"
							mov byte ptr [esi+9],0
							invoke lstrcat,esi,StrAddr(".seem")
							; set curr dir
							invoke GetCL,1,addr bufferz  ;get launchdir
							mov edi,offset bufferz
							invoke lstrlen,addr bufferz
							add edi,eax
							.while byte ptr [edi]!="\"
								dec edi
							.endw
							inc edi
							mov byte ptr [edi],0
							invoke SetCurrentDirectory,addr bufferz
							invoke DeleteFile,addr buffery ;savename
							invoke CreateFile,addr buffery,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0
							mov hSaveFile,eax
							invoke SetFilePointer,hSaveFile,0,0,FILE_BEGIN
							mov eax,offset bufferx
							inc eax
							mov ecx,seem_read_bytes
							dec ecx
							invoke WriteFile,hSaveFile,eax,ecx,addr writtenb,0
							invoke CloseHandle,hSaveFile
						.elseif bl==" " && ax=="fd" ; download file: sd filename
							mov P2kFilesize,1000000 ; max 1 mb
							invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,P2kFilesize
							mov	hMemFile,eax
							mov esi,[W2Kesi] 
							mov NameHW,esi
							mov AttribHW,4 
							invoke Sleep,500														
							invoke CreateThread,0,0,addr P2kDownloadHW,0,0,0
							invoke DialogBoxParam,hInstance, 1700,hWin,OFFSET WaitProc,NULL
							mov esi,[W2Kesi]
							invoke lstrlen,esi
							add esi,eax
							.while byte ptr [esi]!="/"
								dec esi
							.endw
							inc esi
							;mov esi,[W2Kesi]
							invoke GetCL,1,addr buffery  ;get launchdir
							mov edi,offset buffery
							invoke lstrlen,edi
							add edi,eax
							.while byte ptr [edi]!="\"
								dec edi
							.endw
							inc edi
							mov byte ptr [edi],0
							invoke lstrcat,addr buffery,esi
							; save file
							.if P2kFilesize!=0
								invoke DeleteFile,addr buffery
								invoke CreateFile,addr buffery,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0
								mov hSaveFile,eax
								invoke SetFilePointer,hSaveFile,0,0,FILE_END
								invoke WriteFile,hSaveFile,hMemFile,P2kFilesize,addr writtenb,0
								invoke CloseHandle,hSaveFile
							.endif	
							invoke GlobalFree,hMemFile
						.endif
						pop eax
						inc eax
					.endw
							invoke SendMessage,hList1,LVM_GETNEXTITEM,CurrentItem,LVNI_SELECTED ;FOCUSED
							invoke P2kGetFileList2,hWin
							invoke SendMessage,hList2,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc2
							invoke UpdatelParam2
							;invoke ShowWindow,hList1,SW_SHOW
							;invoke ShowWindow,hList2,SW_SHOW
				.endif			
				pop P2kLimit
				mov isBatch,0
				invoke EndDialog,hWin,NULL
			.endif
		.endif
	.else
		mov eax,FALSE
		ret
	.endif
	mov  eax,TRUE
	ret
BatchProc endp
OptionsProc PROC uses edx hWin:HWND,iMsg:DWORD,wParam:WPARAM, lParam:LPARAM
LOCAL ti:TOOLINFO

	.if iMsg==WM_INITDIALOG
		;
		;/* From Iczelions tutorial #27:What we need for a tooltip */
		invoke CreateWindowEx,NULL,ADDR ToolTipsClassName,NULL,TTS_ALWAYSTIP + TTS_BALLOON,CW_USEDEFAULT,\ 
       	CW_USEDEFAULT,CW_USEDEFAULT,CW_USEDEFAULT,NULL,NULL,hInstance,NULL 
		mov hwndTool,eax
		mov ti.cbSize,sizeof TOOLINFO
		mov ti.uFlags,TTF_SUBCLASS
		push hWin
		pop ti.hWnd
		invoke EnumChildWindows,hWin,addr EnumChild,addr ti
		;invoke SendMessage,hwndTool,TTM_GETTIPBKCOLOR,0,0
		;invoke SendMessage,hwndTool,TTM_SETTIPBKCOLOR,eax,0
		;invoke SendMessage,hwndTool,TTM_SETTIPTEXTCOLOR,00000000h,0
		;/* End of What we need for a tooltip */
		;invoke SendMessage,hwndTool,TTM_SETDELAYTIME,TTDT_AUTOMATIC,1000
		push isUSBLAN
		pop isUSBLANold
		invoke SendDlgItemMessage,hWin,1503,WM_SETFONT,hFontL2,1
		invoke GetDlgItem,hWin,1501
		invoke SetFocus,eax
		invoke SendDlgItemMessage,hWin,1501,TBM_SETRANGE,TRUE,510*10000h+10
		invoke SendDlgItemMessage,hWin,1501,TBM_SETTICFREQ,50,10
		mov eax,P2kLimit
		.if eax!=-1
			mov P2kLimit2,eax
		.else
			mov P2kLimit2,510	
		.endif
		invoke SendDlgItemMessage,hWin,1501,TBM_SETPOS,TRUE,P2kLimit2
		invoke SendDlgItemMessage,hWin,1654,WM_SETTEXT,0,addr FileFilter2
		invoke SendDlgItemMessage,hWin,1655,WM_SETTEXT,0,addr ManualCOM
		invoke SendDlgItemMessage,hWin,1572,WM_SETTEXT,0,addr ManualSlot4
		invoke SendDlgItemMessage,hWin,1508,WM_SETTEXT,0,addr cmdUSBLAN
		invoke SendDlgItemMessage,hWin,1517,WM_SETTEXT,0,addr actIP
		invoke dwtoa,InterfaceIndex,addr bufferx
		invoke SendDlgItemMessage,hWin,1656,WM_SETTEXT,0,addr bufferx
		mov iMsg,WM_HSCROLL
		.if isFade==1
			invoke SendDlgItemMessage,hWin,1510,BM_SETCHECK,BST_CHECKED,0
		.else		
			invoke SendDlgItemMessage,hWin,1510,BM_SETCHECK,BST_UNCHECKED,0
		.endif
		.if is3g==0
			invoke SendDlgItemMessage,hWin,1511,BM_SETCHECK,BST_CHECKED,0
		.elseif is3g==1		
			invoke SendDlgItemMessage,hWin,1513,BM_SETCHECK,BST_CHECKED,0
		.elseif is3g==3		
			invoke SendDlgItemMessage,hWin,1512,BM_SETCHECK,BST_CHECKED,0
		.endif
		.if ManualP2k05==1
			invoke SendDlgItemMessage,hWin,1514,BM_SETCHECK,BST_CHECKED,0
		.endif	
		.if isUSBLAN==0
			invoke SendDlgItemMessage,hWin,1502,BM_SETCHECK,BST_CHECKED,0
		.elseif isUSBLAN==1		
			invoke SendDlgItemMessage,hWin,1504,BM_SETCHECK,BST_CHECKED,0
		.elseif isUSBLAN==2		
			invoke SendDlgItemMessage,hWin,1516,BM_SETCHECK,BST_CHECKED,0
		.elseif isUSBLAN==3		
			invoke SendDlgItemMessage,hWin,1521,BM_SETCHECK,BST_CHECKED,0
		.endif
		.if isVerboseLog==1
			invoke SendDlgItemMessage,hWin,1565,BM_SETCHECK,BST_CHECKED,0
		.endif	
		.if isIIndexManual==1
			invoke SendDlgItemMessage,hWin,1566,BM_SETCHECK,BST_CHECKED,0
		.endif	
		.if isNoob==0
			invoke SendDlgItemMessage,hWin,1560,BM_SETCHECK,BST_CHECKED,0
		.endif	
		.if isUpdate==1
			invoke SendDlgItemMessage,hWin,1561,BM_SETCHECK,BST_CHECKED,0
		.endif	
		.if isP2kAutostart==1
			invoke SendDlgItemMessage,hWin,1562,BM_SETCHECK,BST_CHECKED,0
		.endif
		.if isFileFilter==1
			invoke SendDlgItemMessage,hWin,1563,BM_SETCHECK,BST_CHECKED,0
		.endif
		.if isManualCOM==1
			invoke SendDlgItemMessage,hWin,1564,BM_SETCHECK,BST_CHECKED,0
		.endif
		.if isTargetOverride==1
			invoke SendDlgItemMessage,hWin,1570,BM_SETCHECK,BST_CHECKED,0
		.endif
		.if isOverrideSlot4==1
			invoke SendDlgItemMessage,hWin,1571,BM_SETCHECK,BST_CHECKED,0
		.endif
		.if isFixIP==1
			invoke SendDlgItemMessage,hWin,1518,BM_SETCHECK,BST_CHECKED,0
		.endif
;		.if isSlashA==1
;			invoke SendDlgItemMessage,hWin,1550,BM_SETCHECK,BST_CHECKED,0
;		.endif
;		.if isSlashB==1
;			invoke SendDlgItemMessage,hWin,1551,BM_SETCHECK,BST_CHECKED,0
;		.endif
;		.if isSlashC==1
;			invoke SendDlgItemMessage,hWin,1552,BM_SETCHECK,BST_CHECKED,0
;		.endif
;		.if isSlashE==1
;			invoke SendDlgItemMessage,hWin,1553,BM_SETCHECK,BST_CHECKED,0
;		.endif
	.endif	
	.if iMsg==WM_HSCROLL
		invoke SendDlgItemMessage,hWin,1501,TBM_GETPOS,0,0
		mov P2kLimit2,eax
		.if eax!=510
			invoke dwtoa,eax,addr bufferx
			invoke SendDlgItemMessage,hWin,1503,WM_SETTEXT,0,addr bufferx
		.else	
			invoke GetMsgAddr,81
			invoke SendDlgItemMessage,hWin,1503,WM_SETTEXT,0,eax ;addr szUnlimited
			mov eax,-1
			mov P2kLimit2,eax
		.endif
	;
	; dialog háttér
	;
	;.elseif iMsg==WM_CTLCOLORDLG
	;	mov eax,hBrushDwm
	;	Ret		
	.elseif iMsg==WM_CLOSE
		invoke EndDialog,hWin,NULL
	.elseif iMsg==WM_COMMAND
		mov eax,wParam
		mov edx,eax
		shr edx,16
		.if dx==BN_CLICKED
			.if eax==1507   ;cancel
				invoke SendMessage,hWin,WM_CLOSE,NULL,NULL
			.elseif eax==1506   ;ok
				mov eax,P2kLimit2
				mov P2kLimit,eax
				invoke EndDialog,hWin,NULL
				.if isP2kAutostart==1
					invoke lstrcpy,addr bufferx,addr LaunchDir
					invoke lstrcat,addr bufferx,addr szP2kAutostart
					;
					; set starting p2kautostart to registry
					;
					invoke RegCreateKeyEx,HKEY_CURRENT_USER,addr Key4,0,addr RClass,0,KEY_ALL_ACCESS,0,addr hKey4,addr hRetVal
					invoke RegSetValueEx,hKey4,addr Key4Val,0,REG_SZ,addr bufferx,sizeof bufferx
					invoke RegCloseKey,hKey4
					invoke ShellExecute,hWin,NULL,addr bufferx,0,0,SW_SHOW
				.else
					invoke CreateMutex, NULL, TRUE, addr KillP2kA
					mov hMutex,eax
					;
					; kill starting p2kautostart from registry
					;
					invoke RegCreateKeyEx,HKEY_CURRENT_USER,addr Key4,0,addr RClass,0,KEY_ALL_ACCESS,0,addr hKey4,addr hRetVal
					invoke RegSetValueEx,hKey4,addr Key4Val,0,REG_SZ,addr Ver,sizeof Ver
					;invoke RegDeleteKey,hKey4,addr Key4Val					
					invoke RegCloseKey,hKey4
					invoke Sleep,300
					invoke CloseHandle,hMutex
				.endif
				.if isFileFilter==1
					invoke SendDlgItemMessage,hWin,1654,WM_GETTEXT,255,addr FileFilter2
				.else
					invoke lstrcpy,addr FileFilter2,addr FileAll
				.endif
				.if isManualCOM==1
					invoke SendDlgItemMessage,hWin,1655,WM_GETTEXT,255,addr ManualCOM
				.endif
				.if isOverrideSlot4==1
					invoke SendDlgItemMessage,hWin,1572,WM_GETTEXT,255,addr ManualSlot4
				.endif
				.if isIIndexManual==1
					invoke SendDlgItemMessage,hWin,1656,WM_GETTEXT,255,addr bufferx
					invoke atodw,addr bufferx
					mov InterfaceIndex,eax
				.endif
				invoke SendDlgItemMessage,hWin,1508,WM_GETTEXT,255,addr cmdUSBLAN
				invoke SendDlgItemMessage,hWin,1517,WM_GETTEXT,255,addr actIP
				mov eax,isUSBLAN
				.if eax!=isUSBLANold
					push isUSBLAN
					pop isUSBLANold
					invoke MessageBox,hWin,StrAddr("Mode changed, application will restart now."),StrAddr("Warning !!"),MB_ICONASTERISK+MB_OK
					mov startInfo.dwFlags,STARTF_USESHOWWINDOW
					mov startInfo.wShowWindow,SW_HIDE
					invoke CreateProcess,NULL,StrAddr("restart"),NULL,NULL,FALSE,\ 
	    		      NORMAL_PRIORITY_CLASS,\ 
	          		  NULL,NULL,ADDR startInfo,ADDR processInfo
	          		invoke SendMessage,hWnd,WM_CLOSE,0,0  
				.endif
				.if _DevIF!=0 && isUSBLAN==0 ;|| _DevIF!=0 && isUSBLAN==3
					invoke P2K_Vibrate
					invoke GetVolInfo
				.endif	
				.if isUSBLAN==3
					.if isFileFilter==1
					.else
						mov isFileFilter,1	
						invoke lstrcpy,addr FileFilter,StrAddr("/a/*")
					.endif
					invoke UpdateDropdown
				.endif
			.elseif eax==1510   ; Fade checkbox
				mov eax,isFade
				xor eax,1
				mov isFade,eax
			.elseif eax==1511   ; 3g checkbox
				mov is3g,0
			.elseif eax==1512   ; 3g checkbox
				mov is3g,3
			.elseif eax==1513   ; 3g checkbox
				mov is3g,1
			.elseif eax==1514   ; p2kl05
				xor ManualP2k05,1
			.elseif eax==1565   ; log
				xor isVerboseLog,1
			.elseif eax==1566   ; IIndex
				xor isIIndexManual,1
			.elseif eax==1560   ; n00b alerts checkbox
				xor isNoob,1
			.elseif eax==1561   ; update checkbox
				xor isUpdate,1
			.elseif eax==1562   ; p2kautostart checkbox
				xor isP2kAutostart,1
			.elseif eax==1563   ; filter checkbox
				xor isFileFilter,1
			.elseif eax==1564   ; filter checkbox
				xor isManualCOM,1
			.elseif eax==1570   ; 
				xor isTargetOverride,1
			.elseif eax==1502   ; 
				mov isUSBLAN,0
			.elseif eax==1504  ; 
				mov isUSBLAN,1
			.elseif eax==1516  ; 
				mov isUSBLAN,2
			.elseif eax==1521  ; 
				mov isUSBLAN,3
			.elseif eax==1518  ; 
				xor isFixIP,1
;			.elseif eax==1550   ; drive checkbox
;				mov isSlashA,1
;				mov isSlashB,0
;				mov isSlashC,0
;				mov isSlashE,0
;			.elseif eax==1551   ; drive checkbox
;				mov isSlashA,0
;				mov isSlashB,1
;				mov isSlashC,0
;				mov isSlashE,0
;			.elseif eax==1552   ; drive checkbox
;				mov isSlashA,0
;				mov isSlashB,0
;				mov isSlashC,1
;				mov isSlashE,0
;			.elseif eax==1553   ; drive checkbox
;				mov isSlashA,0
;				mov isSlashB,0
;				mov isSlashC,0
;				mov isSlashE,1
			.endif
		.endif
	.else
		mov eax,FALSE
		ret
	.endif
	mov  eax,TRUE
	ret
OptionsProc endp
AboutProc PROC uses edx hWin:HWND,iMsg:DWORD,wParam:WPARAM, lParam:LPARAM
	.if iMsg==WM_INITDIALOG
		;invoke SendDlgItemMessage,hWin,1202,STM_SETIMAGE,IMAGE_BITMAP,hBackgr2
		invoke SendDlgItemMessage,hWin,1204,WM_SETFONT,hFontL2,1
		invoke SendDlgItemMessage,hWin,1205,WM_SETFONT,hFontL2,1
		invoke SendDlgItemMessage,hWin,1206,WM_SETFONT,hFontL2,1
		invoke SendDlgItemMessage,hWin,1207,WM_SETFONT,hFontL2,1
		invoke SendDlgItemMessage,hWin,1202,WM_SETFONT,hFontL2,1
		invoke SendDlgItemMessage,hWin,1216,WM_SETFONT,hFontL2,1
		;invoke SendDlgItemMessage,hWin,1211,WM_SETFONT,hFontL3,1
		invoke GetDlgItem,hWin,1211
		mov hURL,eax
		invoke GetDlgItem,hWin,1212
		mov hURL2,eax
		invoke GetDlgItem,hWin,1215
		mov hURL3,eax
		invoke GetDlgItem,hWin,1217
		mov hURL4,eax
		invoke SendMessage,hURL,HLM_SETHOTCOLOR,0,AboutHotLinkColor
		invoke SendMessage,hURL,HLM_SETTEXTCOLOR,0,AboutLinkColor
		invoke SendMessage,hURL,HLM_SETUNDERLINE,0,TRUE
		invoke SendMessage,hURL,HLM_SETTYPE,0,HLINK_URL
		invoke SetWindowText,hURL,OFFSET MM_Url
		invoke SendMessage,hURL4,HLM_SETHOTCOLOR,0,AboutHotLinkColor
		invoke SendMessage,hURL4,HLM_SETTEXTCOLOR,0,AboutLinkColor
		invoke SendMessage,hURL4,HLM_SETUNDERLINE,0,TRUE
		invoke SendMessage,hURL4,HLM_SETTYPE,0,HLINK_URL
		invoke SetWindowText,hURL4,OFFSET MM_Url4
		invoke SendMessage,hURL3,HLM_SETHOTCOLOR,0,AboutHotLinkColor
		invoke SendMessage,hURL3,HLM_SETTEXTCOLOR,0,AboutLinkColor
		invoke SendMessage,hURL3,HLM_SETUNDERLINE,0,TRUE
		invoke SendMessage,hURL3,HLM_SETTYPE,0,HLINK_URL
		invoke SetWindowText,hURL3,OFFSET MM_Url3
		invoke SendMessage,hURL2,HLM_SETHOTCOLOR,0,AboutHotLinkColor
		invoke SendMessage,hURL2,HLM_SETTEXTCOLOR,0,AboutLinkColor
		invoke SendMessage,hURL2,HLM_SETUNDERLINE,0,TRUE
		invoke SendMessage,hURL2,HLM_SETTYPE,0,HLINK_EMAIL
		invoke SetWindowText,hURL2,OFFSET MM_Url2
		invoke SendMessage,hURL2,HLM_SETSUBJECT,0,OFFSET Esubject
		invoke SendMessage,hURL2,HLM_SETBODY,0,OFFSET Ebody
		
	.elseif iMsg==WM_CLOSE
		invoke EndDialog,hWin,NULL
	;
	; dialog háttér
	;
	.elseif iMsg==WM_CTLCOLORDLG
		mov eax,hBrushDwm
		Ret		
	.ElseIf iMsg==WM_CTLCOLORSTATIC
		invoke SetTextColor, wParam, AboutTextColor
		Invoke 	SetBkMode, wParam, TRANSPARENT
		invoke GetStockObject,NULL_BRUSH
		Ret
;	.elseif iMsg==WM_NOTIFY
;		push edi
;		mov edi,lParam
;		assume edi:ptr NMHDR
;		mov eax,[edi].idFrom
;		.if eax==1211
;			nop
;		.endif
;		assume edi:nothing
;		pop edi		
	.elseif iMsg==WM_COMMAND
		mov eax,wParam
		mov edx,eax
		shr edx,16
		.if dx==BN_CLICKED
			.if eax==1203   ;ok
				invoke SendMessage,hWin,WM_CLOSE,NULL,NULL
			.endif
		.endif
	.else
		mov eax,FALSE
		ret
	.endif
	mov  eax,TRUE
	ret
AboutProc endp
WaitProc PROC hWin:HWND,iMsg:DWORD,wParam:WPARAM, lParam:LPARAM
	.if iMsg==WM_INITDIALOG
		invoke SetTimer,hWin,5555,100,0
	.elseif iMsg==WM_TIMER
		;invoke dwtoa,Row2,addr bufferz
		;invoke SendDlgItemMessage,hWin,1702,WM_SETTEXT,0,addr bufferz
		.if isThreadComplete==1
			mov iMsg,WM_CLOSE
		.endif
	.endif	
	.if iMsg==WM_CLOSE
		invoke KillTimer,hWin,5555
		invoke EndDialog,hWin,NULL
	.elseif iMsg==WM_COMMAND
	.else
		mov eax,FALSE
		ret
	.endif
	mov  eax,TRUE
	ret
WaitProc endp
GetLocalFilename proc hWin:HWND,StartItem:DWORD
LOCAL lvi:LV_ITEM
LOCAL buffer[256]:BYTE
				.if LeftRightS==0
					invoke SendMessage,hList1,LVM_GETNEXTITEM,StartItem,LVNI_SELECTED  ; eax=-1 if no more selected
					.if eax==-1
						ret  ; no more
					.endif
					mov lvi.iItem,eax
					mov CurrentItem,eax
					mov PrevPos1,eax
					mov lvi.iSubItem,1
					mov lvi.imask,LVIF_TEXT
					lea eax,buffer
					mov lvi.pszText,eax
					mov lvi.cchTextMax,256
					; get the item
					invoke SendMessage,hList1,LVM_GETITEM,0,addr lvi    ; buffer:filename
					lea eax,buffer
					.if byte ptr [eax]=="<"
						mov isDir,1 
					.else	
						mov isDir,0 
					.endif
					mov eax,CurrentItem
					mov lvi.iSubItem,0
					mov lvi.iItem,eax
					;mov CurrentItem,eax
					;mov PrevPos1,eax
					mov lvi.imask,LVIF_TEXT
					lea eax,buffer
					mov lvi.pszText,eax
					mov lvi.cchTextMax,256
					invoke SendMessage,hList1,LVM_GETITEM,0,addr lvi    ; buffer:filename
					invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr DestDir
					invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr szDrive1
					invoke SetCurrentDirectory,addr szDrive1
				.elseif LeftRightS==1
					invoke SendMessage,hList2,LVM_GETNEXTITEM,StartItem,LVNI_SELECTED  ; eax=-1 if no more selected
					.if eax==-1
						ret  ; no more
					.endif
					mov lvi.iItem,eax
					mov CurrentItem,eax
					mov PrevPos2,eax
					mov lvi.iSubItem,1
					mov lvi.imask,LVIF_TEXT
					lea eax,buffer
					mov lvi.pszText,eax
					mov lvi.cchTextMax,256
					; get the item
					invoke SendMessage,hList2,LVM_GETITEM,0,addr lvi    ; buffer:filename
					lea eax,buffer
					.if byte ptr [eax]=="<"
						mov isDir,1 
					.else	
						mov isDir,0 
					.endif
					mov eax,CurrentItem
					mov lvi.iSubItem,0
					mov lvi.iItem,eax
					;mov CurrentItem,eax
					;mov PrevPos2,eax
					mov lvi.imask,LVIF_TEXT
					lea eax,buffer
					mov lvi.pszText,eax
					mov lvi.cchTextMax,256
					invoke SendMessage,hList2,LVM_GETITEM,0,addr lvi    ; buffer:filename
					invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr DestDir
					invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr szDrive2
					invoke SetCurrentDirectory,addr szDrive2
				.endif
				lea eax,buffer
				invoke lstrcpy,addr bufferx,eax
	ret
GetLocalFilename endp
;
; Statusbar szöveg
;
SetStatusText proc nPart:DWORD, nStyle:DWORD, lpText:DWORD
    mov eax, nPart
    or eax, nStyle
	invoke SendMessage, hStatus, SB_SETTEXT, eax, lpText
    invoke InvalidateRect, hStatus, 0, TRUE
	ret
SetStatusText endp
WndProc proc uses esi edi hWin:HWND,uMsg:UINT,wParam:WPARAM,lParam:LPARAM
LOCAL ti:TOOLINFO
LOCAL lvi:LV_ITEM
LOCAL lvc:LV_COLUMN 
LOCAL buffer[512]:BYTE
LOCAL buffer2[512]:BYTE
LOCAL lvk:LV_KEYDOWN
LOCAL sfi:SHFILEINFO
LOCAL Item:DWORD

	mov		eax,uMsg
	.if eax==WM_CREATE
	.elseif eax==WM_INITDIALOG
		push	hWin
		pop		hWnd
		push	hWin
		pop		hWinV
		;
		; Splash animation
		;
		invoke SendDlgItemMessage,hWin,1030,WAGM_LOADGIFFROMRESOURCE,hInstance,555
		invoke SendDlgItemMessage,hWin,1030,WAGM_SETBKCOLOR,TRUE,0 ;0dcb26dh
		invoke GetDlgItem,hWin,1030
		mov hSplash,eax
		invoke GetDesktopWindow
		push eax
		invoke SetParent,hSplash,eax
		pop eax
		invoke GetWindowPlacement,hWin,addr MainPlacement
;		mov eax,MainPlacement.rcNormalPosition.right
;		sub eax,MainPlacement.rcNormalPosition.left
;		mov ebx,MainPlacement.rcNormalPosition.bottom
;		sub ebx,MainPlacement.rcNormalPosition.top
;		shr eax,1
;		shr ebx,1
;		mov MainPlacement.rcNormalPosition.left,eax
;		sub MainPlacement.rcNormalPosition.left,160
;		mov MainPlacement.rcNormalPosition.right,eax
;		add MainPlacement.rcNormalPosition.right,160
;		mov MainPlacement.rcNormalPosition.top,ebx
;		sub MainPlacement.rcNormalPosition.top,120
;		mov MainPlacement.rcNormalPosition.bottom,ebx
;		add MainPlacement.rcNormalPosition.bottom,120
		invoke SetWindowPlacement,hSplash,addr MainPlacement
		;invoke ShowWindow,hWin,SW_HIDE
		
		invoke GetModuleFileName,0,addr LaunchDir,511
		mov edi,offset LaunchDir
		invoke lstrlen,addr LaunchDir
		add edi,eax
		.while byte ptr [edi]!="\"
			dec edi
		.endw
		mov byte ptr [edi],0
    	;
    	; set IPREPORT and FTPDRIVE path
    	;
    	invoke lstrcpy,addr CmdDelIp,addr CmdDelIpTemp
    	invoke lstrcat,addr CmdDelIp,addr LaunchDir
    	invoke lstrcat,addr CmdDelIp,addr CmdReport
    	invoke lstrcat,addr CmdDelIp,addr szQ
    	invoke lstrcpy,addr CmdIp,addr CmdIpTemp
    	invoke lstrcat,addr CmdIp,addr LaunchDir
    	invoke lstrcat,addr CmdIp,addr CmdReport
    	invoke lstrcat,addr CmdIp,addr szQ
    	invoke lstrcpy,addr CmdInsFtpDrive,addr CmdTInsFtpDrive
    	invoke lstrcat,addr CmdInsFtpDrive,addr LaunchDir
    	invoke lstrcat,addr CmdInsFtpDrive,addr CmdFtpDrive1
    	invoke lstrcpy,addr CmdFtpDrive,addr szQ
    	invoke lstrcat,addr CmdFtpDrive,addr LaunchDir
    	invoke lstrcat,addr CmdFtpDrive,addr CmdFtpDrive2
    	invoke lstrcpy,addr CmdFtpServCp,addr CmdFtpServCp1
    	invoke lstrcat,addr CmdFtpServCp,addr LaunchDir
    	invoke lstrcat,addr CmdFtpServCp,addr CmdFtpServCp2
    	invoke lstrcat,addr CmdFtpServCp,addr LaunchDir
    	invoke lstrcat,addr CmdFtpServCp,addr CmdFtpServCp3
    	invoke lstrcat,addr CmdFtpServCp,addr LaunchDir
    	invoke lstrcat,addr CmdFtpServCp,addr CmdFtpServCp4

    	invoke lstrcpy,addr CmdDelLog,addr LaunchDir
    	invoke lstrcat,addr CmdDelLog,addr CmdLog
		invoke DeleteFile,addr CmdDelLog
		;
		; read lang file
		;
		invoke ReadLangFile,hWin
		.if eax==-1
			invoke SendMessage,hWin,WM_CLOSE,0,0
		.else
			invoke GetMsgAddr,42 ; lang file loaded
			invoke logstat,eax
			invoke logstat,addr LaunchDir
	    	invoke SetCurrentDirectory,addr LaunchDir
	    .endif
	    invoke SetButtonLabels,hWin	
    	invoke LoadConfig,hWin
					;
					; read seem file
					;
					invoke ReadSeemList,hWin
					invoke ReadSeemCat,hWin
					;
					; keyb acclerators
					;
					invoke LoadAccelerators,hInstance,IDR_ACCEL
					mov hAccel,eax
					;
					; App.Icon és Alt-tab icon
					;
					invoke LoadIcon,hInstance,4000
					mov hIcon,eax
					invoke LoadIcon,hInstance,4000
					mov hIconPhone,eax
					invoke SendMessage,hWin,WM_SETICON,ICON_BIG,hIcon ;alt-tab icon
					invoke SendMessage,hWin,WM_SETICON,ICON_SMALL,hIcon ;alt-tab icon
					;
					; load res bitmaps
					;
					;invoke LoadBitmap,hInstance,1201
					invoke GetDlgItem,hWin,1008
					mov hF2,eax
					invoke GetDlgItem,hWin,1007
					mov hF3,eax
					invoke GetDlgItem,hWin,1026
					mov hF4,eax
					invoke GetDlgItem,hWin,1027
					mov hF5,eax
					invoke GetDlgItem,hWin,1004
					mov hF6,eax
			
					invoke GetDlgItem,hWin,1009
					mov hF7,eax
					invoke GetDlgItem,hWin,1011
					mov hF8,eax
					invoke GetDlgItem,hWin,1010
					mov hF9,eax
					invoke GetDlgItem,hWin,1014
					mov hBar,eax
					invoke GetDlgItem,hWin,1001
					mov hLog,eax
					;invoke GetDlgItem,hWin,1017
					;mov hLogo,eax
					;invoke GetDlgItem,hWin,1016
					;mov hDir1,eax
					;invoke GetDlgItem,hWin,1015
					;mov hDir2,eax
					invoke GetDlgItem,hWin,1013
					mov hReread2,eax
					invoke GetDlgItem,hWin,1006
					mov hLB2,eax
					invoke GetDlgItem,hWin,1005
					mov hLB1,eax
					invoke GetDlgItem,hWin,1002
					mov hList1,eax
					invoke GetDlgItem,hWin,1003
					mov hList2,eax
					invoke GetDlgItem,hWin,1016
					mov hHead1,eax
					invoke GetDlgItem,hWin,1015
					mov hHead2,eax
					invoke GetDlgItem,hWin,1025
					mov hStatus,eax
			;		invoke GetDlgItem,hWin,1029
			;		mov hSplitter,eax
					invoke SendMessage, hStatus, SB_SETPARTS, 4, ADDR dwParts ; setup 2 panels  
					invoke GetMsgAddr,77
					invoke SetStatusText, 3, 0,eax ; ADDR szType		; set style / text		
					invoke GetMsgAddr,78
					invoke SetStatusText, 1, 0,eax ; ADDR szName		; set style / text		
					invoke GetMsgAddr,79
					invoke SetStatusText, 2, 0,eax ; ADDR szFiles	; set style / text		
					invoke GetMsgAddr,80
					invoke SetStatusText, 0, 0,eax ; ADDR szFree		; set style / text		
					
					;invoke SendMessage,hList1,WM_SETFOCUS,0,0
				    ; set bold font
			    	INVOKE     lstrcpy, addr lf.lfFaceName, addr FontMS2
				    mov     lf.lfHeight, -13
			    	mov     lf.lfWeight, 600
				    INVOKE     CreateFontIndirect, addr lf
			    	mov     hFontL2, eax    ; Listview font
			;    	INVOKE     lstrcpy, addr lf.lfFaceName, addr FontMS
			;	    mov     lf.lfHeight, -12
			;   	mov     lf.lfWeight, 600
			;	    INVOKE     CreateFontIndirect, addr lf
			;    	mov     hFontL, eax    ; Listview font
			    	
					invoke CreateFont,15,6,0,0,FW_BOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,6,DEFAULT_PITCH,StrAddr ( "Arial" )
			    	mov hFontL, eax	    	; Listview font
					; set log font
					invoke CreateFont,15,7,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,6,DEFAULT_PITCH,StrAddr ( "Courier new" )
			;		invoke CreateFont,13,7,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,6,DEFAULT_PITCH,StrAddr ( "Lucida console" )
			    	mov hFontlog, eax	    
					invoke SendDlgItemMessage,hWin,1001,WM_SETFONT,hFontlog,TRUE
			
			    	
			    	INVOKE     lstrcpy, addr lf.lfFaceName, addr FontMSfixed
				    mov     lf.lfQuality,200
				    mov     lf.lfHeight, -12
				    ;mov     lf.lfWidth, -5
			    	mov     lf.lfWeight, 300
				    INVOKE     CreateFontIndirect, addr lf
			    	mov     hFontL3, eax    ; Listview font
					;invoke SendDlgItemMessage,hWin,1012,WM_GETFONT,0,0
					;mov hFontLo,eax ; original font    	
				    INVOKE     SendMessage, hList1, WM_SETFONT, hFontL, 1
			    	INVOKE     SendMessage, hList2, WM_SETFONT, hFontL, 1
			    	INVOKE     SendDlgItemMessage,hWin,1015, WM_SETFONT, hFontL, 1
			    	INVOKE     SendDlgItemMessage,hWin,1016, WM_SETFONT, hFontL, 1
			    	;INVOKE     SendDlgItemMessage,hWin,1005, WM_SETFONT, hFontL3,1 ;drive select
			    	;INVOKE     SendDlgItemMessage,hWin,1006, WM_SETFONT, hFontL3,1
			    	;INVOKE     SendDlgItemMessage,hWin,1012, WM_SETFONT, hFontL, 1
			    	;INVOKE     SendDlgItemMessage,hWin,1013, WM_SETFONT, hFontL, 1
			    	
			    	;;invoke LoadCursor,hInstance,IDC_WAIT
			    	;;mov hWaitCursor,eax
			    	;;invoke SetClassLong,hWin,GCL_HCURSOR,hWaitCursor
					;
					; imagelists, buttons with icon
					;		
					; view
					invoke ImageList_Create,24,24,ILC_COLOR24 OR ILC_MASK,0,5
					mov hImagelist1,eax
					mov ButtImList1.himl,eax
					invoke LoadIcon,hInstance,4100
					invoke ImageList_AddIcon,hImagelist1,eax
					invoke LoadIcon,hInstance,4101
					invoke ImageList_AddIcon,hImagelist1,eax
					invoke LoadIcon,hInstance,4102
					invoke ImageList_AddIcon,hImagelist1,eax
			
					invoke LoadIcon,hInstance,4103
					invoke ImageList_AddIcon,hImagelist1,eax
					invoke LoadIcon,hInstance,4100
					invoke ImageList_AddIcon,hImagelist1,eax
					;mov ButtImList1.margin.left,0	
					;mov ButtImList1.margin.top,0	
					invoke SendDlgItemMessage,hWin,1007,BCM_SETIMAGELIST,0,addr ButtImList1
					; edit
					invoke ImageList_Create,24,24,ILC_COLOR24 OR ILC_MASK,0,5
					mov hImagelist8,eax
					mov ButtImList8.himl,eax
					invoke LoadIcon,hInstance,4800
					invoke ImageList_AddIcon,hImagelist8,eax
					invoke LoadIcon,hInstance,4801
					invoke ImageList_AddIcon,hImagelist8,eax
					invoke LoadIcon,hInstance,4802
					invoke ImageList_AddIcon,hImagelist8,eax
					invoke LoadIcon,hInstance,4803
					invoke ImageList_AddIcon,hImagelist8,eax
					invoke LoadIcon,hInstance,4800
					invoke ImageList_AddIcon,hImagelist8,eax
					;mov ButtImList1.margin.left,0	
					;mov ButtImList1.margin.top,0	
					invoke SendDlgItemMessage,hWin,1026,BCM_SETIMAGELIST,0,addr ButtImList8
					; attrib
					invoke ImageList_Create,24,24,ILC_COLOR24 OR ILC_MASK,0,5
					mov hImagelist2,eax
					mov ButtImList2.himl,eax
					invoke LoadIcon,hInstance,4200
					invoke ImageList_AddIcon,hImagelist2,eax
					invoke LoadIcon,hInstance,4201
					invoke ImageList_AddIcon,hImagelist2,eax
					invoke LoadIcon,hInstance,4202
					invoke ImageList_AddIcon,hImagelist2,eax
					invoke LoadIcon,hInstance,4203
					invoke ImageList_AddIcon,hImagelist2,eax
					invoke LoadIcon,hInstance,4200
					invoke ImageList_AddIcon,hImagelist2,eax
					;mov ButtImList2.margin.left,0	
					;mov ButtImList2.margin.top,8	
					invoke SendDlgItemMessage,hWin,1008,BCM_SETIMAGELIST,0,addr ButtImList2
					; copy
					invoke ImageList_Create,24,24,ILC_COLOR24 OR ILC_MASK,0,5
					mov hImagelist3,eax
					mov ButtImList3.himl,eax
					invoke LoadIcon,hInstance,4300
					invoke ImageList_AddIcon,hImagelist3,eax
					invoke LoadIcon,hInstance,4301
					invoke ImageList_AddIcon,hImagelist3,eax
					invoke LoadIcon,hInstance,4302
					invoke ImageList_AddIcon,hImagelist3,eax
					invoke LoadIcon,hInstance,4303
					invoke ImageList_AddIcon,hImagelist3,eax
					invoke LoadIcon,hInstance,4300
					invoke ImageList_AddIcon,hImagelist3,eax
					;mov ButtImList3.margin.left,0	
					;mov ButtImList3.margin.top,8	
					invoke SendDlgItemMessage,hWin,1027,BCM_SETIMAGELIST,0,addr ButtImList3
					; move
					invoke ImageList_Create,24,24,ILC_COLOR24 OR ILC_MASK,0,5
					mov hImagelist4,eax
					mov ButtImList4.himl,eax
					invoke LoadIcon,hInstance,4400
					invoke ImageList_AddIcon,hImagelist4,eax
					invoke LoadIcon,hInstance,4401
					invoke ImageList_AddIcon,hImagelist4,eax
					invoke LoadIcon,hInstance,4402
					invoke ImageList_AddIcon,hImagelist4,eax
					invoke LoadIcon,hInstance,4403
					invoke ImageList_AddIcon,hImagelist4,eax
					invoke LoadIcon,hInstance,4400
					invoke ImageList_AddIcon,hImagelist4,eax
					;mov ButtImList4.margin.left,0
					;mov ButtImList4.margin.top,8	
					invoke SendDlgItemMessage,hWin,1004,BCM_SETIMAGELIST,0,addr ButtImList4
					; new
					invoke ImageList_Create,24,24,ILC_COLOR24 OR ILC_MASK,0,5
					mov hImagelist5,eax
					mov ButtImList5.himl,eax
					invoke LoadIcon,hInstance,4500
					invoke ImageList_AddIcon,hImagelist5,eax
					invoke LoadIcon,hInstance,4501
					invoke ImageList_AddIcon,hImagelist5,eax
					invoke LoadIcon,hInstance,4502
					invoke ImageList_AddIcon,hImagelist5,eax
					invoke LoadIcon,hInstance,4503
					invoke ImageList_AddIcon,hImagelist5,eax
					invoke LoadIcon,hInstance,4500
					invoke ImageList_AddIcon,hImagelist5,eax
					;mov ButtImList5.margin.left,0
					;mov ButtImList5.margin.top,8	
					invoke SendDlgItemMessage,hWin,1009,BCM_SETIMAGELIST,0,addr ButtImList5
					; delete
					invoke ImageList_Create,24,24,ILC_COLOR24 OR ILC_MASK,0,5
					mov hImagelist6,eax
					mov ButtImList6.himl,eax
					invoke LoadIcon,hInstance,4600
					invoke ImageList_AddIcon,hImagelist6,eax
					invoke LoadIcon,hInstance,4601
					invoke ImageList_AddIcon,hImagelist6,eax
					invoke LoadIcon,hInstance,4602
			
					invoke ImageList_AddIcon,hImagelist6,eax
					invoke LoadIcon,hInstance,4603
					invoke ImageList_AddIcon,hImagelist6,eax
					invoke LoadIcon,hInstance,4600
					invoke ImageList_AddIcon,hImagelist6,eax
					;mov ButtImList6.margin.left,0
					;mov ButtImList6.margin.top,8	
					invoke SendDlgItemMessage,hWin,1011,BCM_SETIMAGELIST,0,addr ButtImList6
					; restart
					invoke ImageList_Create,24,24,ILC_COLOR24 OR ILC_MASK,0,5
					mov hImagelist9,eax
					mov ButtImList9.himl,eax
					invoke LoadIcon,hInstance,4900
					invoke ImageList_AddIcon,hImagelist9,eax
					invoke LoadIcon,hInstance,4901
					invoke ImageList_AddIcon,hImagelist9,eax
					invoke LoadIcon,hInstance,4902
					invoke ImageList_AddIcon,hImagelist9,eax
					invoke LoadIcon,hInstance,4903
					invoke ImageList_AddIcon,hImagelist9,eax
					invoke LoadIcon,hInstance,4900
					invoke ImageList_AddIcon,hImagelist9,eax
					;mov ButtImList6.margin.left,0
					;mov ButtImList6.margin.top,8	
					invoke SendDlgItemMessage,hWin,1010,BCM_SETIMAGELIST,0,addr ButtImList9
					; reread
					invoke ImageList_Create,16,16,ILC_COLOR24 OR ILC_MASK,0,5
					mov hImagelist7,eax
					mov ButtImList7.himl,eax
					invoke LoadIcon,hInstance,4700
					invoke ImageList_AddIcon,hImagelist7,eax
					invoke LoadIcon,hInstance,4701
					invoke ImageList_AddIcon,hImagelist7,eax
					invoke LoadIcon,hInstance,4702
					invoke ImageList_AddIcon,hImagelist7,eax
					invoke LoadIcon,hInstance,4703
					invoke ImageList_AddIcon,hImagelist7,eax
					invoke LoadIcon,hInstance,4700
					invoke ImageList_AddIcon,hImagelist7,eax
					;mov ButtImList7.margin.left,0
					;mov ButtImList7.margin.right,-14
					;mov ButtImList7.margin.top,16	
					invoke SendDlgItemMessage,hWin,1012,BCM_SETIMAGELIST,0,addr ButtImList7
					invoke SendDlgItemMessage,hWin,1013,BCM_SETIMAGELIST,0,addr ButtImList7
					;
					;/* From Iczelions tutorial #27:What we need for a tooltip */
					invoke CreateWindowEx,NULL,ADDR ToolTipsClassName,NULL,TTS_ALWAYSTIP + TTS_BALLOON,CW_USEDEFAULT,\ 
			       	CW_USEDEFAULT,CW_USEDEFAULT,CW_USEDEFAULT,NULL,NULL,hInstance,NULL 
					mov hwndTool,eax
					mov ti.cbSize,sizeof TOOLINFO
					mov ti.uFlags,TTF_SUBCLASS
					push hWin
					pop ti.hWnd
					invoke EnumChildWindows,hWin,addr EnumChild,addr ti
					;invoke SendMessage,hwndTool,TTM_SETDELAYTIME,TTDT_AUTOMATIC,1000
					;invoke SendMessage,hwndTool,TTM_GETTIPBKCOLOR,0,0
					;invoke SendMessage,hwndTool,TTM_SETTIPBKCOLOR,eax,0
					;invoke SendMessage,hwndTool,TTM_SETTIPTEXTCOLOR,00000000h,0
					;/* End of What we need for a tooltip */
					;
					;
					; Listview háttér
					;
					;invoke LoadBitmap,hInstance,503
					invoke BitmapFromResource,hInstance,502  ; about watermark jpg!!
					mov ListWp1.hbm,eax
					mov ListWp1.xOffsetPercent,50
					mov ListWp1.yOffsetPercent,50
					mov ListWp1.ulFlags,LVBKIF_STYLE_TILE+LVBKIF_SOURCE_HBITMAP  ;TILE
					;
					invoke SendMessage,hList1,LVM_SETTEXTBKCOLOR,0,CLR_NONE
					invoke SendMessage,hList1,LVM_SETBKIMAGE,0,addr ListWp1
					invoke SendMessage,hList2,LVM_SETTEXTBKCOLOR,0,CLR_NONE
					invoke SendMessage,hList2,LVM_SETBKIMAGE,0,addr ListWp1
					;
					; Install new LV/LB procedures
					;
					invoke SetWindowLong,hList1,GWL_WNDPROC,ADDR LVProc
					mov OldLVProc,eax
					invoke SetWindowLong,hLog,GWL_WNDPROC,ADDR LBProc
					mov OldLBProc,eax
					;
					; Get rightclick submenu
					;	
					invoke GetMenu,hWin
					mov hMenu,eax
					invoke GetSubMenu,hMenu,0
					invoke GetSubMenu,eax,0
					mov hRMenu,eax ; rightclick menu
					;
					; get commandline parameter (get full path of strting location to write registry)
					;
					mov esi,CommandLine
					.IF BYTE PTR [esi]=='"'
						inc esi ; '"'
					.endif	
					invoke lstrcpy,addr bufferx,esi
					mov esi,offset bufferx
					mov al,[esi]
					.while al!='"'
						inc esi
						mov al,[esi]
					.endw
					mov byte ptr[esi],0
					;
					; set registry entries
					;
					invoke lstrcpy,addr buffery,addr bufferx
					invoke lstrcat,addr bufferx,addr Key2Val
					;invoke lstrcpy,addr buffery,addr LaunchDir
					invoke lstrcat,addr buffery,addr Key3Val
					invoke RegCreateKeyEx,HKEY_CLASSES_ROOT,addr Key1,0,0,REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,0,addr hKey1,addr hRetVal
					invoke RegCreateKeyEx,HKEY_CLASSES_ROOT,addr Key2,0,0,REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,0,addr hKey2,addr hRetVal
					invoke RegCreateKeyEx,HKEY_CLASSES_ROOT,addr Key3,0,0,REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,0,addr hKey3,addr hRetVal
					invoke RegSetValueEx,hKey1,0,0,REG_SZ,addr Key1Val,sizeof Key1Val
					invoke RegSetValueEx,hKey2,0,0,REG_SZ,addr bufferx,sizeof bufferx
					invoke RegSetValueEx,hKey3,0,0,REG_SZ,addr buffery,sizeof buffery
					invoke RegCloseKey,hKey1
					invoke RegCloseKey,hKey2
					invoke RegCloseKey,hKey3
					;
					; Check s4m installed or not.
					;
					invoke RegOpenKeyEx,HKEY_CLASSES_ROOT,addr szS4MKey,0,KEY_QUERY_VALUE,addr hKey
					.if eax!=0 ; if not, assign s4m filetype to p2kc
						invoke RegCreateKeyEx,HKEY_CLASSES_ROOT,addr KeyS1,0,0,REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,0,addr hKeyS1,addr hRetVal
						invoke RegSetValueEx,hKeyS1,0,0,REG_SZ,addr Key1Val,sizeof Key1Val
						invoke RegCloseKey,hKeyS1
					.endif
					;
					; get commandline 1st parameter if any, *.p2kc batch file
					;
					invoke GetCL,1,addr bufferx  ;1:ok, 4:no param
					.if eax==1
						;
						; if at the end of bufferx there is .s4m then drop a msgbox, and exit
						;
						mov esi,offset bufferx
						invoke lstrlen,addr bufferx
						add esi,eax
						mov eax,[esi-4]
						.if eax=="m4s."
							invoke GetMsgAddr,89
							invoke MessageBox,hWin,addr szWarnS4m,eax,MB_OK + MB_ICONINFORMATION
							invoke SendMessage,hWin,WM_CLOSE,NULL,NULL
						.endif
						invoke DialogBoxParam,hInstance, 1600,hWin,OFFSET BatchProc,NULL
						invoke ShowCurrentFocus1,hWin
						.if _DevIF==1 ;DevFound==1
							;
							; send phone restart, and exit
							;
							invoke GetMsgAddr,89
							invoke MessageBox,hWin,addr szEndBatch,eax,MB_YESNO + MB_ICONINFORMATION
							.if eax==IDYES
								;invoke SendMessage,hWin,WM_COMMAND,1010,0
								invoke P2K_Restart
							.endif
						.elseif DevFound!=999
						invoke GetMsgAddr,89
							invoke MessageBox,hWin,addr szNotConn,eax,MB_OK + MB_ICONERROR
						.endif			
						invoke DeleteObject,hBrushDwm
						invoke DeleteObject,hBackgr
						invoke DestroyWindow,hWin
;						invoke GlobalFree,SearchBuf_Ptr
;						; free lang file mem
;						invoke GlobalFree,hMemLang
;						invoke GlobalFree,hMemLangPtrs
;						; free seem file mem
;						invoke GlobalFree,hMemSeem
;						invoke GlobalFree,hMemSeemPtrs
;						invoke GlobalFree,hMemSeemF
;						invoke GlobalFree,hMemSeemFPtrs
;						invoke KillTimer,hWin,TimerID
;						invoke KillTimer,hWin,ScanTimerID
						return 0  ; kill app          	
						;invoke SendMessage,hWin,WM_CLOSE,NULL,NULL
					.endif
				;
				; set starting drives (left/right)
				;
				;mov Drive1,2 ; c:
				;mov Drive2,2
				.if Drive1<5
					mov Drive1,6
				.endif
				.if Drive2<5
					mov Drive2,6
				.endif
				invoke lstrcpy,addr P2kDirectory1,addr P2kDirInit ; /
				invoke lstrcpy,addr P2kDirectory2,addr P2kDirInit
				; get iconindexes
			    INVOKE SHGetFileInfo, addr szP2kC, 0, addr sfi, sizeof SHFILEINFO,SHGFI_SYSICONINDEX or SHGFI_SMALLICON or SHGFI_TYPENAME or SHGFI_ATTRIBUTES
			    mov ebx,sfi.iIcon
			    mov P2kIconIndex,ebx
			    INVOKE SHGetFileInfo,StrAddr("Templates\_.hlp"), 0, addr sfi, sizeof SHFILEINFO,SHGFI_SYSICONINDEX or SHGFI_SMALLICON or SHGFI_TYPENAME or SHGFI_ATTRIBUTES
			    mov ebx,sfi.iIcon
			    mov P2kQIconIndex,ebx
			    INVOKE SHGetFileInfo,StrAddr("c:\windows\unvise32.exe"), 0, addr sfi, sizeof SHFILEINFO,SHGFI_SYSICONINDEX or SHGFI_SMALLICON or SHGFI_TYPENAME or SHGFI_ATTRIBUTES
			    mov ebx,sfi.iIcon
			    mov P2kDIconIndex,ebx
				; get drive list
				invoke GetDrives1
				;insert 2 p2k items
				invoke SetP2kCB1,hWin
				; get drive list
				invoke GetDrives2
				invoke SetP2kCB2,hWin
		
				invoke InsertColumn
				invoke SendDlgItemMessage,hWin,1006,CB_SETCURSEL,Drive2,0
				;invoke SendDlgItemMessage,hWin,1006,CB_SELECTSTRING,-1,Drive2
				
				;invoke SetCurrDir2,hWin,Drive2
				invoke SetCurrentDirectory,addr szDrive2
				invoke GetCurrentDirectory,255,addr bufferx
				invoke SendDlgItemMessage,hWin,1015,WM_SETTEXT,0,addr bufferx
				
				mov FileNameSortOrder,3
				invoke FillFileInfo2,hWin
				;mov FileNameSortOrder,3
				;invoke SendMessage,hList2,LVM_SORTITEMS,3,addr CompareFunc2
				;invoke UpdatelParam2
				;mov FileNameSortOrder,3
		
				invoke SendDlgItemMessage,hWin,1005,CB_SETCURSEL,Drive1,0
					
				;invoke SetCurrDir1,hWin,Drive1
				invoke SetCurrentDirectory,addr szDrive1
				invoke GetCurrentDirectory,255,addr bufferx
				invoke SendDlgItemMessage,hWin,1016,WM_SETTEXT,0,addr bufferx
				
				mov FileNameSortOrder,3
				invoke FillFileInfo1,hWin
				;
				mov PrevPos1,0
				mov PrevPos2,0
				invoke SelectFirst1,0
				mov stay_quiet,0
		        ;invoke GetMsgAddr,39
				;invoke logstat,eax ;addr szStarted
				;invoke LoadCursor,NULL,IDC_APPSTARTING
				;invoke SetCursor,eax
				;nop
				;mov InitCompleted,1
				
				invoke GetWindowLong,hList1,GWL_WNDPROC
				mov OldList1WndProc,eax
				mov eax,offset NewList1Proc
				invoke SetWindowLong,hList1,GWL_WNDPROC,eax
				invoke GetWindowLong,hList2,GWL_WNDPROC
				mov OldList2WndProc,eax
				mov eax,offset NewList2Proc
				invoke SetWindowLong,hList2,GWL_WNDPROC,eax
		
				
				invoke lstrcpy,addr bufferx,addr LaunchDir
				invoke lstrcat,addr bufferx,StrAddr("\.log")
				invoke CreateFile,addr bufferx,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0
				mov hSaveFile,eax
				invoke CloseHandle,hSaveFile
			.if ThreadStarted==0		
				;
				; start thread
				;
				mov ThreadStarted,1
				mov startInfo.dwFlags,STARTF_USESHOWWINDOW
				mov startInfo.wShowWindow,SW_HIDE
				invoke CreateProcess,NULL,addr CmdDelIp,NULL,NULL,FALSE,\ 
		              NORMAL_PRIORITY_CLASS,\ 
		              NULL,NULL,ADDR startInfo,ADDR processInfo
				mov startInfo.wShowWindow,SW_SHOW
				mov startInfo.dwFlags,STARTF_USESHOWWINDOW
				mov startInfo.wShowWindow,SW_HIDE
				invoke CreateProcess,NULL,addr CmdInsFtpDrive,NULL,NULL,FALSE,\ 
		              NORMAL_PRIORITY_CLASS,\ 
		              NULL,NULL,ADDR startInfo,ADDR processInfo
				mov startInfo.wShowWindow,SW_SHOW
				mov fromThread,0
				mov fromThread2,0
				.if isUSBLAN==0
					invoke FindUSBClass
	                push    offset Thread_ID
	                push    0
	                push    0
	                push    offset CheckP2kStatusThread
	                push    0
	                push    0
	                call    CreateThread
	            .else
					invoke FindUSBLAN
	                push    offset Thread_ID
	                push    0
	                push    0
	                push    offset CheckUSBLANStatusThread
	                push    0
	                push    0
	                call    CreateThread
	            .endif	    
	        .endif	    
		;
		; Fade in
		;
;		.if isFade==1 ;OSVer.dwMajorVersion>4
;			invoke GetWindowLongA,hWin,GWL_EXSTYLE
;			or eax,80000h              ;WS_EX_LAYERED = 80000h
;			mov LayeredSave,eax
;			invoke SetWindowLongA,hWin,GWL_EXSTYLE,eax
;			invoke SetLayeredWindowAttributes,hWin,0,0,2   ;LWA_ALPHA = 2
;			mov LayeredOrig,eax
;			mov eax,10
;		.else 
;			mov eax,1
;		.endif
;		;	
;		; setting timers
;		;
;		invoke SetTimer,hWin,2000,eax,0   	; 10 msec
;		mov TimerID,eax
;		mov TransTimer,0
;		invoke SetTimer,hWin,2001,200,0 ; 500 msec check another instance started
;		mov ScanTimerID,eax

;		.if isP2kAutostart==1
;			invoke lstrcpy,addr bufferx,addr LaunchDir
;			invoke lstrcat,addr bufferx,addr szP2kAutostart
;			;
;			; set starting p2kautostart to registry
;			;
;			invoke RegCreateKeyEx,HKEY_CURRENT_USER,addr Key4,0,addr RClass,0,KEY_ALL_ACCESS,0,addr hKey4,addr hRetVal
;			invoke RegSetValueEx,hKey4,addr Key4Val,0,REG_SZ,addr bufferx,sizeof bufferx
;			invoke RegCloseKey,hKey4
;			invoke ShellExecute,hWin,NULL,addr bufferx,0,0,SW_SHOW
;		.else
;			invoke CreateMutex, NULL, TRUE, addr KillP2kA
;			mov hMutex,eax
;			;
;			; kill starting p2kautostart from registry
;			;
;			invoke RegCreateKeyEx,HKEY_CURRENT_USER,addr Key4,0,addr RClass,0,KEY_ALL_ACCESS,0,addr hKey4,addr hRetVal
;			invoke RegSetValueEx,hKey4,addr Key4Val,0,REG_SZ,addr Ver,sizeof Ver
;			;invoke RegDeleteKey,hKey4,addr Key4Val					
;			invoke RegCloseKey,hKey4
;			invoke Sleep,100
;			invoke CloseHandle,hMutex
;		.endif
;********************                
; init from wm_timer
;********************                
;				.if isP2kAutostart==1
;					invoke lstrcpy,addr bufferx,addr LaunchDir
;					invoke lstrcat,addr bufferx,addr szP2kAutostart
;					invoke ShellExecute,hWin,NULL,addr bufferx,0,0,SW_SHOW
;				.endif	
		;
		; Init timer
		;
		invoke SetTimer,hWin,2001,2800,0 ;SplashTimerVal,0   	
		mov SplashTimerID,eax
		invoke SetTimer,hWin,2002,1000,0 ;update   	
		mov UpdateTimerID,eax
;					;
;					; n00b reminder: Check P2kLimit and partitions
;					;
;					.if isNoob==1
;						.if P2kLimit!=-1
;						invoke GetMsgAddr,85
;						invoke lstrcpy,addr buffer,eax 
;						invoke lstrcat,addr buffer,addr crlf 
;						invoke GetMsgAddr,86
;						invoke lstrcat,addr buffer,eax 
;						invoke lstrcat,addr buffer,addr crlf 
;						invoke GetMsgAddr,87
;						invoke lstrcat,addr buffer,eax 
;						invoke lstrcat,addr buffer,addr crlf 
;						invoke GetMsgAddr,88
;						invoke lstrcat,addr buffer,eax 
;							invoke GetMsgAddr,89
;							invoke MessageBox,hWin,addr buffer,eax,MB_ICONEXCLAMATION + MB_OK
;						.endif
;						invoke GetMsgAddr,82
;						invoke lstrcpy,addr buffer,eax ;addr szN00b1
;						.if isSlashA==1
;							invoke lstrcat,addr buffer,addr szSlashA
;						.endif
;						.if isSlashB==1
;							invoke lstrcat,addr buffer,addr szSlashB
;						.endif
;						.if isSlashC==1
;							invoke lstrcat,addr buffer,addr szSlashC
;						.endif
;						.if isSlashE==1
;							invoke lstrcat,addr buffer,addr szSlashE
;						.endif
;						invoke lstrcat,addr buffer,addr crlf
;						invoke GetMsgAddr,83
;						invoke lstrcat,addr buffer,eax ;addr szN00b2
;						invoke GetMsgAddr,84
;						invoke MessageBox,hWin,addr buffer,eax,MB_ICONEXCLAMATION + MB_OK
;					.endif	
			;invoke LoadPos,hWin

    .ELSEIF eax==WM_TIMER
		mov eax,wParam
		.if	eax==SplashTimerID
			invoke KillTimer,hWin,SplashTimerID
			;
			; Stop Splash
			;
			invoke ShowWindow,hSplash,SW_HIDE
			invoke LoadPos,hWin
		.elseif	eax==UpdateTimerID
			invoke KillTimer,hWin,UpdateTimerID
				.if isUpdate==1		
					;
					; check new version on homepage
					;
					mov esi,offset Esubject  ;  actual ver
					invoke lstrlen,addr Esubject
					add esi,eax
					sub esi,3
					mov eax,[esi]
					xchg al,ah
					shl eax,8
					sub esi,3
					mov ax,[esi] ; eax now "V322"
					mov Ver,eax
					invoke logstat,StrAddr ( "Open Internet connection. " )
					invoke InternetOpen,addr AppName,INTERNET_OPEN_TYPE_DIRECT,NULL,NULL,0
					mov iHwn,eax
					invoke InternetOpenUrl,iHwn,addr P2kcURL,0,0,INTERNET_FLAG_RELOAD,0
					.if eax!=0 ; connect ?
						mov fDown,eax
						invoke logstat,StrAddr ( "Check if update available. " )
						invoke InternetReadFile,fDown,addr bufferz,255,addr writtenb
						invoke InternetCloseHandle,fDown
						mov eax,writtenb
						mov esi,offset bufferz
						mov edi,esi
						add edi,writtenb
						mov byte ptr [edi],0
						mov eax,[esi]
						add esi,14
						push esi
						.if eax!=Ver
							;invoke InternetOpenUrl,iHwn,addr P2kcURL3,0,0,INTERNET_FLAG_RELOAD,0
							;nop
							;.if eax==NULL
								invoke InternetOpenUrl,iHwn,addr P2kcURL2,0,0,INTERNET_FLAG_RELOAD,0
								mov fDown,eax
								invoke InternetReadFile,fDown,addr buffery,255,addr writtenb
								invoke GetMsgAddr,89
								invoke MessageBox,hWin,addr buffery,eax,MB_YESNO + MB_ICONINFORMATION
							;.else
								
							;.endif		
								.if eax==IDYES
									pop esi
									invoke logstat,esi
									invoke ShellExecute,hWin,0,addr szExplorer,esi,0,SW_SHOW
									invoke ShellExecute,hWin,addr szOpen,esi,0,0,SW_SHOW
									nop
								.else
									pop esi	
								.endif
						.else
							pop esi	
							invoke logstat,StrAddr ( "Sorry, no update available yet. " )
						.endif
						invoke InternetCloseHandle,iHwn
						invoke InternetCloseHandle,fDown
					.else
						invoke logstat,StrAddr ( "Cannot establish Internet connection. " )
					.endif
				.endif			
		.endif
		
;;*********** test hidden files
;		invoke ReadHiddenList,hWin
;		mov ecx,nHiddenFCount
;		mov esi,hMemHiddenFPtrs
;		.while ecx!=0
;			pusha
;			invoke logstat,[esi]
;			popa
;			add esi,4
;			dec ecx
;		.endw	

	;
	; dialog háttér
	;
	;.elseif eax==WM_CTLCOLORDLG
	;	mov eax,hBrushD
	;	Ret		
;	.elseif eax==WM_CTLCOLOREDIT
		;mov eax,lParam
		;.if eax==hEdit1
	;		invoke SetBkColor,wParam,00h ;color
	;	.endif			
		;mov eax,COLOR_BTNFACE+1 ;brush
;		Ret
	;
	; Needed for rightclick menu
	;	
    .ELSEIF eax==WM_CONTEXTMENU   ;has user right clicked mouse?
      mov eax, lParam             ;if so, show the popup menu			
      and eax, 0ffffh
      mov ebx, lParam
      shr ebx, 16
      ;add ebx,6
      mov esi,wParam
      .if esi==hList1 || esi==hList2
      	invoke TrackPopupMenu, hRMenu, TPM_LEFTALIGN, eax, ebx, 0, hWin, 0
      .endif		
    ;  
	; needed for splitter
	;	
	.elseif eax==WM_MOUSEMOVE
		mov eax,lParam
		mov ebx,lParam
		shr ebx,10h
		and eax,0ffffh
		mov SplitterX,eax
		mov SplitterY,ebx
		.if eax > ListPlacement1.rcNormalPosition.right && eax < ListPlacement2.rcNormalPosition.left && ebx < ListPlacement2.rcNormalPosition.bottom
			invoke LoadCursor,NULL,IDC_SIZEWE
			invoke SetCursor,eax
			invoke SetCapture,hWin
		.else
			mov eax,SplitterX
			mov ebx,SplitterY
			.if wParam!=MK_LBUTTON  ; no left mousebutton press, only cruise
				invoke ReleaseCapture
			.else	; left button pressed, dragging !!
				mov ebx,ListPlacement2.rcNormalPosition.right
				sub ebx,eax
				.if eax>210 && ebx>210
					mov eax,SplitterX
					mov ListPlacement1.rcNormalPosition.right,eax
					mov DirPlacement1.rcNormalPosition.right,eax
					invoke SetWindowPlacement,hList1,addr ListPlacement1
					invoke SetWindowPlacement,hHead1,addr DirPlacement1
					mov eax,SplitterX
					add eax,4
					mov ListPlacement2.rcNormalPosition.left,eax
					mov DirPlacement2.rcNormalPosition.left,eax
					mov LBPlacement2.rcNormalPosition.left,eax
					add eax,134
					mov LBPlacement2.rcNormalPosition.right,eax
					inc eax
					mov RereadPlacement2.rcNormalPosition.left,eax
					add eax,75
					mov RereadPlacement2.rcNormalPosition.right,eax
					invoke SetWindowPlacement,hList2,addr ListPlacement2
					invoke SetWindowPlacement,hHead2,addr DirPlacement2
					invoke SetWindowPlacement,hReread2,addr RereadPlacement2
					invoke SetWindowPlacement,hLB2,addr LBPlacement2
;					mov esi,SplitterX
;					mov ListPlacement1.rcNormalPosition.right,esi
;					mov DirPlacement1.rcNormalPosition.right,esi
;					invoke SetWindowPlacement,hList1,addr ListPlacement1
;					invoke SetWindowPlacement,hHead1,addr DirPlacement1
;					add esi,4
;					mov ListPlacement2.rcNormalPosition.left,esi
;					mov DirPlacement2.rcNormalPosition.left,esi
;					mov LBPlacement2.rcNormalPosition.left,esi
;					add esi,134
;					mov LBPlacement2.rcNormalPosition.right,esi
;					inc esi
;					mov RereadPlacement2.rcNormalPosition.left,esi
;					add esi,75
;					mov RereadPlacement2.rcNormalPosition.right,esi
;					invoke SetWindowPlacement,hList2,addr ListPlacement2
;					invoke SetWindowPlacement,hHead2,addr DirPlacement2
;					invoke SetWindowPlacement,hReread2,addr RereadPlacement2
;					invoke SetWindowPlacement,hLB2,addr LBPlacement2
					mov eax,ListPlacement1.rcNormalPosition.right
					sub eax,ListPlacement1.rcNormalPosition.left
					.if eax>328
						sub eax,188	
						invoke SendMessage,hList1,LVM_SETCOLUMNWIDTH,0,eax
					.endif
					mov eax,ListPlacement2.rcNormalPosition.right

					sub eax,ListPlacement2.rcNormalPosition.left
					.if eax>328
						sub eax,188	
						invoke SendMessage,hList2,LVM_SETCOLUMNWIDTH,0,eax
					.endif
				.else
					invoke ReleaseCapture
					.if Drive2==0
						invoke P2kGetFileList2,hWin
					.else	
						invoke FillFileInfo2,hWin
					.endif	
			        ;invoke SendMessage,hWin,WM_COMMAND,1013,0
					xor eax,eax
					ret
				.endif		
			.endif			
		.endif	
    .elseif eax == WM_LBUTTONUP
         INVOKE     LoadCursor, 0, IDC_ARROW
         INVOKE     SetCursor, eax
         INVOKE     ReleaseCapture
			invoke ShowWindow,hLB2,SW_HIDE
			invoke ShowWindow,hReread2,SW_HIDE
			invoke ShowWindow,hLB2,SW_SHOW
			invoke ShowWindow,hReread2,SW_SHOW
         .if Drive2==0
         	invoke P2kGetFileList2,hWin
         .else
         	invoke FillFileInfo2,hWin
         .endif
         ;invoke SendMessage,hWin,WM_COMMAND,1013,0
    ;
    ; Needed for ownerdrawn listbox
    ;     
	.elseif eax==WM_MEASUREITEM
		.if wParam==1005 || wParam==1006
			mov edi,[lParam]
			mov [edi+MEASUREITEMSTRUCT.itemHeight],16
		.endif	
	.elseif eax==WM_DRAWITEM
		.if wParam==1005 || wParam==1006
			mov edi,[lParam]
			mov eax,[edi+DRAWITEMSTRUCT.itemState]
			test eax,ODS_SELECTED
			.if	!ZERO?
				; selected
				invoke GetSysColor,COLOR_HIGHLIGHTTEXT
				invoke SetTextColor,[edi+DRAWITEMSTRUCT.hdc],eax
				mov SaveTxColor,eax
				invoke GetSysColor,COLOR_HIGHLIGHT
				invoke SetBkColor,[edi+DRAWITEMSTRUCT.hdc],eax
				mov SaveBkColor,eax
			.else	
				; normal
				invoke GetSysColor,COLOR_WINDOWTEXT
				invoke SetTextColor,[edi+DRAWITEMSTRUCT.hdc],eax
				mov SaveTxColor,eax
				invoke GetSysColor,COLOR_WINDOW
				invoke SetBkColor,[edi+DRAWITEMSTRUCT.hdc],eax
				mov SaveBkColor,eax
			.endif
			invoke SendMessage,[edi+DRAWITEMSTRUCT.hwndItem],CB_GETLBTEXT,[edi+DRAWITEMSTRUCT.itemID],addr DrawBuffer
			mov ebx,edi
			add ebx,DRAWITEMSTRUCT.rcItem
			mov eax,[ebx]
			add eax,22
			mov [ebx],eax
			mov eax,[ebx+4]
			;;add eax,2
			mov [ebx+4],eax
			invoke lstrlen,addr DrawBuffer
			; draw text
			invoke ExtTextOut,[edi+DRAWITEMSTRUCT.hdc],[edi+DRAWITEMSTRUCT.rcItem.left],[edi+DRAWITEMSTRUCT.rcItem.top],ETO_OPAQUE+ETO_CLIPPED,ebx,addr DrawBuffer,eax,0
			invoke SetTextColor,[edi+DRAWITEMSTRUCT.hdc],SaveTxColor
			invoke SetBkColor,[edi+DRAWITEMSTRUCT.hdc],SaveBkColor
			; draw icon
			invoke SendMessage,[edi+DRAWITEMSTRUCT.hwndItem],CB_GETITEMDATA,[edi+DRAWITEMSTRUCT.itemID],0
			mov ecx,eax
			mov ebx,edi
			add ebx,DRAWITEMSTRUCT.rcItem
			mov eax,[ebx]
			sub eax,20
			mov [ebx],eax
			mov eax,[ebx+4]
			mov [ebx+4],eax
			invoke ImageList_Draw,hSystemImageList,ecx,[edi+DRAWITEMSTRUCT.hdc],[edi+DRAWITEMSTRUCT.rcItem.left],[edi+DRAWITEMSTRUCT.rcItem.top],ILD_TRANSPARENT
		.endif
;	.elseif eax==WM_SETCURSOR
;;		.if isHide==1
;;			invoke LoadCursor,NULL,IDC_WAIT
;;			invoke SetCursor,eax
;;		.else	
;;			invoke LoadCursor,NULL,IDC_ARROW
;;			invoke SetCursor,eax
;;		.endif
;		.if isSplitterHover==1
;			invoke LoadCursor,NULL,IDC_SIZEWE
;			invoke SetCursor,eax
;		.else	
;			invoke LoadCursor,NULL,IDC_ARROW
;			invoke SetCursor,eax
;		.endif
;		ret	
	;
	; Needed for fade-out
	;
;	.elseif eax==WM_TIMER
;		mov eax,wParam
;;		.if eax==ScanTimerID
;;			invoke OpenMutex,MUTEX_ALL_ACCESS,FALSE,addr P2kInstance2
;;			nop
;;			.if eax!=0
;;				invoke SendMessage,hWin,WM_SYSCOMMAND,SC_RESTORE,0
;;			.endif
;		.if eax==TimerID
;			.if isFade==1 ;OSVer.dwMajorVersion>4
;				invoke LoadPos,hWin
;				invoke SetLayeredWindowAttributes,hWin,0,TransTimer,2   ;LWA_ALPHA = 2
;				.if TransTimer<=250
;					inc TransTimer
;					inc TransTimer
;					inc TransTimer
;					inc TransTimer
;					inc TransTimer
;				.else
;					;invoke GetWindowLongA,hWin,GWL_EXSTYLE
;					;and eax,7ffffh                                	; WS_EX_LAYERED = 80000h
;					mov eax,LayeredOrig
;					invoke SetWindowLongA,hWin,GWL_EXSTYLE,eax
;					invoke KillTimer,hWin,TimerID
;				.endif	
;			.else		
;					invoke LoadPos,hWin
;					invoke KillTimer,hWin,TimerID
;			.endif		
;			.if TransTimer==5 || TransTimer==0
;				.if isP2kAutostart==1
;					invoke lstrcpy,addr bufferx,addr LaunchDir
;					invoke lstrcat,addr bufferx,addr szP2kAutostart
;					invoke ShellExecute,hWin,NULL,addr bufferx,0,0,SW_SHOW
;				.endif	
;				.if isUpdate==1		
;					;
;					; check new version on homepage
;					;
;					mov esi,offset Esubject  ;  actual ver
;					invoke lstrlen,addr Esubject
;					add esi,eax
;					sub esi,3
;					mov eax,[esi]
;					xchg al,ah
;					shl eax,8
;					sub esi,3
;					mov ax,[esi] ; eax now "V322"
;					mov Ver,eax
;					invoke logstat,StrAddr ( "Open Internet connection. " )
;					invoke InternetOpen,addr AppName,INTERNET_OPEN_TYPE_DIRECT,NULL,NULL,0
;					mov iHwn,eax
;					invoke InternetOpenUrl,iHwn,addr P2kcURL,0,0,INTERNET_FLAG_RELOAD,0
;					.if eax!=0 ; connect ?
;						mov fDown,eax
;						invoke logstat,StrAddr ( "Check if update available. " )
;						invoke InternetReadFile,fDown,addr bufferx,255,addr writtenb
;						invoke InternetCloseHandle,fDown
;						mov eax,writtenb
;						mov esi,offset bufferx
;						mov edi,esi
;						add edi,writtenb
;						mov byte ptr [edi],0
;						mov eax,[esi]
;						add esi,5
;						push esi
;						.if eax!=Ver
;							;invoke InternetOpenUrl,iHwn,addr P2kcURL3,0,0,INTERNET_FLAG_RELOAD,0
;							;nop
;							;.if eax==NULL
;								invoke InternetOpenUrl,iHwn,addr P2kcURL2,0,0,INTERNET_FLAG_RELOAD,0
;								mov fDown,eax
;								invoke InternetReadFile,fDown,addr buffery,255,addr writtenb
;								invoke GetMsgAddr,89
;								invoke MessageBox,hWin,addr buffery,eax,MB_YESNO + MB_ICONINFORMATION
;							;.else
;								
;							;.endif		
;							.if eax==IDYES
;								pop esi
;								invoke logstat,esi
;								invoke ShellExecute,hWin,0,addr szExplorer,esi,0,SW_SHOW
;								invoke ShellExecute,hWin,addr szOpen,esi,0,0,SW_SHOW
;								nop
;							.else
;								pop esi	
;							.endif
;						.else	
;							invoke logstat,StrAddr ( "Sorry, no update available yet. " )
;						.endif
;						invoke InternetCloseHandle,iHwn
;						invoke InternetCloseHandle,fDown
;					.else
;						invoke logstat,StrAddr ( "Cannot establish Internet connection. " )
;					.endif
;				.endif			
;					;
;					; n00b reminder: Check P2kLimit and partitions
;					;
;					.if isNoob==1
;						.if P2kLimit!=-1
;						invoke GetMsgAddr,85
;						invoke lstrcpy,addr buffer,eax 
;						invoke lstrcat,addr buffer,addr crlf 
;						invoke GetMsgAddr,86
;						invoke lstrcat,addr buffer,eax 
;						invoke lstrcat,addr buffer,addr crlf 
;						invoke GetMsgAddr,87
;						invoke lstrcat,addr buffer,eax 
;						invoke lstrcat,addr buffer,addr crlf 
;						invoke GetMsgAddr,88
;						invoke lstrcat,addr buffer,eax 
;							invoke GetMsgAddr,89
;							invoke MessageBox,hWin,addr buffer,eax,MB_ICONEXCLAMATION + MB_OK
;						.endif
;						invoke GetMsgAddr,82
;						invoke lstrcpy,addr buffer,eax ;addr szN00b1
;						.if isSlashA==1
;							invoke lstrcat,addr buffer,addr szSlashA
;						.endif
;						.if isSlashB==1
;							invoke lstrcat,addr buffer,addr szSlashB
;						.endif
;						.if isSlashC==1
;							invoke lstrcat,addr buffer,addr szSlashC
;						.endif
;						.if isSlashE==1
;							invoke lstrcat,addr buffer,addr szSlashE
;						.endif
;						invoke lstrcat,addr buffer,addr crlf
;						invoke GetMsgAddr,83
;						invoke lstrcat,addr buffer,eax ;addr szN00b2
;						invoke GetMsgAddr,84
;						invoke MessageBox,hWin,addr buffer,eax,MB_ICONEXCLAMATION + MB_OK
;					.endif	
;					;
;					; get commandline 1st parameter if any, *.p2kc batch file
;					;
;					invoke GetCL,1,addr bufferx  ;1:ok, 4:no param
;					.if eax==1
;						;
;						; if at the end of bufferx there is .s4m then drop a msgbox, and exit
;						;
;						mov esi,offset bufferx
;						invoke lstrlen,addr bufferx
;						add esi,eax
;						mov eax,[esi-4]
;						.if eax=="m4s."
;							invoke GetMsgAddr,89
;							invoke MessageBox,hWin,addr szWarnS4m,eax,MB_OK + MB_ICONINFORMATION
;							invoke SendMessage,hWin,WM_CLOSE,NULL,NULL
;						.endif
;						invoke DialogBoxParam,hInstance, 1600,hWin,OFFSET BatchProc,NULL
;						invoke ShowCurrentFocus1,hWin
;						.if DevFound==1
;							;
;							; send phone restart, and exit
;							;
;							invoke GetMsgAddr,89
;							invoke MessageBox,hWin,addr szEndBatch,eax,MB_YESNO + MB_ICONINFORMATION
;							.if eax==IDYES
;								;invoke SendMessage,hWin,WM_COMMAND,1010,0
;								invoke P2K_Restart
;							.endif
;						.elseif DevFound!=999
;						invoke GetMsgAddr,89
;							invoke MessageBox,hWin,addr szNotConn,eax,MB_OK + MB_ICONERROR
;						.endif			
;						invoke DeleteObject,hBrushDwm
;						invoke DeleteObject,hBackgr
;						invoke DestroyWindow,hWin
;						invoke GlobalFree,SearchBuf_Ptr
;						; free lang file mem
;						invoke GlobalFree,hMemLang
;						invoke GlobalFree,hMemLangPtrs
;						; free seem file mem
;						invoke GlobalFree,hMemSeem
;						invoke GlobalFree,hMemSeemPtrs
;						invoke GlobalFree,hMemSeemF
;						invoke GlobalFree,hMemSeemFPtrs
;						invoke KillTimer,hWin,TimerID
;						invoke KillTimer,hWin,ScanTimerID
;						return 0  ; kill app          	
;						;invoke SendMessage,hWin,WM_CLOSE,NULL,NULL
;					.endif
;			.endif
;		.endif	
	.elseif eax==WM_CHAR
		nop
	.elseif eax==WM_ACTIVATE
		.if LeftRight==0
			invoke SetFocus,hList1
		.else
			invoke SetFocus,hList2
		.endif
	.elseif eax==WM_COMMAND
		mov		eax,wParam
		and		eax,0FFFFh
		.if eax==10017
			invoke SendMessage,hWin,WM_CLOSE,0,0
		.elseif eax==IDM_HELP_ABOUT
			invoke DialogBoxParam,hInstance, 1200,hWin,OFFSET AboutProc,NULL
		.elseif eax==10019 ; re-connect
            .if isManualCOM==0
            	call COM_Find
            	.if eax!=0
            		call COM_Find_New
                	.if eax!=0
                		call COM_Find_New2
                	.endif	
            	.endif	
            .else
            	invoke lstrcpy,addr keyval_buf,addr ManualCOM
            	mov eax,0	
            .endif	
			.if eax==0
				invoke logstat,StrAddr("*** MODEM device found, try to switch USBLAN mode.")
				invoke Switch_modeLAN
				invoke logstat,StrAddr("Waiting for USBLAN device...")
				invoke Sleep,2000
				invoke ReadIpFile,hWin
			.else
				invoke logstat,StrAddr("!! Sorry, no MODEM device found at all.")
			.endif
		.elseif eax==10020 ;restart app.
				mov startInfo.dwFlags,STARTF_USESHOWWINDOW
				mov startInfo.wShowWindow,SW_HIDE
				invoke CreateProcess,NULL,StrAddr("restart"),NULL,NULL,FALSE,\ 
    		      NORMAL_PRIORITY_CLASS,\ 
          		  NULL,NULL,ADDR startInfo,ADDR processInfo
          		invoke SendMessage,hWnd,WM_CLOSE,0,0  
		.elseif eax==10018 ;del favourite folder
			invoke SendDlgItemMessage,hWin,1005,CB_FINDSTRING,-1,StrAddr("_")
			.if eax!=CB_ERR
				push eax
				invoke SendDlgItemMessage,hWin,1005,CB_DELETESTRING,eax,0
				pop eax
				invoke SendDlgItemMessage,hWin,1006,CB_DELETESTRING,eax,0
			.endif
		.elseif eax==10001 ;add favourite folder
			invoke lstrcpy,addr bufferx,StrAddr("_")
			invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr szDrive1
			invoke lstrcat,addr bufferx,addr szDrive1
			; user drive
			invoke SendDlgItemMessage,hWin,1005,CB_ADDSTRING,0,addr bufferx ;StrAddr("_F:\RadAsm\")
			invoke SendMessage,hLB1,CB_SETITEMDATA,eax,P2kIconIndex
			invoke SendDlgItemMessage,hWin,1006,CB_ADDSTRING,0,addr bufferx ;StrAddr("_F:\RadAsm\")
			invoke SendMessage,hLB2,CB_SETITEMDATA,eax,P2kIconIndex
			; save to .config file
			invoke lstrcpy,addr Fav1,addr bufferx
		.elseif eax==10015 ;restart
			call P2K_Restart
		.elseif eax==10006 ;AT mode
			call P2K_AT
		.elseif eax==10007 ;Options dialog
			invoke DialogBoxParam,hInstance, 1500,hWin,OFFSET OptionsProc,NULL
		.elseif eax==10009 ;View
			mov eax,IDC_BTN1
		.elseif eax==10010 ;Edit
			mov eax,IDC_BTN23
		.elseif eax==10016 ;Attrib
			mov eax,IDC_BTN3
		.elseif eax==10011 ;Copy
			mov eax,IDC_BTN24
		.elseif eax==10012 ;Move
			mov eax,IDC_BTN2
		.elseif eax==10013 ;New
			mov eax,IDC_BTN4
		.elseif eax==10014 ;Del
			mov eax,IDC_BTN6
		.elseif eax==10015 ;restart
			mov eax,IDC_BTN5
		.elseif eax==10005 ; seem functions
			invoke DialogBoxParam,hInstance, 1850,hWin,OFFSET SeemFuncProc,NULL
		.elseif eax==10003 ; discover seem numbers
			mov eax,900 ;2ffh
			inc eax
			shl eax,16
			invoke SendMessage,hBar,PBM_SETRANGE,0,eax
			invoke SendMessage,hBar,PBM_SETSTEP,1,0
			invoke SendMessage,hBar,PBM_SETPOS,0,0
			invoke GetMsgAddr,125
			invoke SendDlgItemMessage,hWnd,1001,LB_ADDSTRING,0,eax
			inc eax
			push eax			
			mov P2k_Timeout,100
			mov Item,-1 ;1dh ;-1
			.while Item!=900 ;2ffh
				inc Item
				mov eax,Item
		        push    offset phone_model
		        .if Item<6
	            	push 0 
	            .else
	            	push 1
	            .endif		
	            push    0
		        push    1
	            push    Item
	            mov stay_quiet,1
	            invoke Cmd_RDELEM

	            mov stay_quiet,0
	            .if eax==0
					invoke dw2ah,Item,addr phone_model
					mov esi,offset phone_model
					mov byte ptr [esi+8],0
					add esi,4
					invoke logstat,esi
	            .endif
				invoke SendDlgItemMessage,hWin,1014,PBM_STEPIT,0,0
			.endw
			mov P2k_Timeout,1388h
			; save to file
			invoke lstrcpy,addr bufferx,addr LaunchDir
			invoke lstrcat,addr bufferx,addr szBackslash
			invoke lstrcat,addr bufferx,StrAddr ("Seem.lst")
			invoke DeleteFile,offset bufferx
			invoke CreateFile,offset bufferx,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0
			mov hSaveFile,eax
			invoke SendDlgItemMessage,hWin,1001,LB_GETCOUNT,0,0
			mov esi,eax
			pop edi
			.while edi!=esi
				push edi
				push esi
				invoke SendDlgItemMessage,hWin,1001,LB_GETTEXT,edi,addr bufferx
				invoke lstrlen,addr bufferx
				;invoke SendDlgItemMessage,hWin,1001,LB_GETTEXTLEN,edi,0
				invoke WriteFile,hSaveFile,addr bufferx,eax,addr writtenb,0
				invoke WriteFile,hSaveFile,addr crlf,2,addr writtenb,0
				pop esi
				pop edi
				inc edi
			.endw	
			invoke CloseHandle,hSaveFile
			;re-read file
			invoke ReadSeemList,hWin
		.elseif eax==10004 ; old dialog
			invoke DialogBoxParam,hInstance, 1800,hWin,OFFSET SeemProc,NULL
		.endif	
;--------------- restart ---------------------			
		.if eax==IDC_BTN5 ;1010
			mov P2kReady,0
			mov P2kRestart,1
			call P2K_Restart
;--------------- edit ---------------------			
		.elseif eax==IDC_BTN23 ;1026
		;
		;		invoke CreateMutex, NULL, FALSE, addr SuspendP2kA
		;		mov hSMutex,eax
		;
		
			push LeftRight
			pop LeftRightS
			invoke GetLocalFilename,hWin,-1
			.if Drive1<4 && LeftRightS==0			
				;p2k edit left
				; 1:download to temp folder buffer=filename
				; dest filename = Launchdir + "\Temp\" + buffer
				invoke lstrcpy,Addr buffery,addr LaunchDir
				invoke lstrcat,Addr buffery,addr Tempdir
				invoke SendMessage,hList1,LVM_GETNEXTITEM,-1,LVNI_SELECTED ;FOCUSED
				mov esi,eax
				invoke P2kCopy_down,esi,hWin,hList1,addr buffery
				invoke lstrcat,addr buffery,addr bufferx ;dest filename+path
				; run xvi32 to view file
				invoke lstrcpy,addr bufferx,StrAddr ('"')
				invoke lstrcat,addr bufferx,addr buffery
				invoke lstrcpy,addr bufferz,addr buffery
				invoke lstrcat,addr bufferx,StrAddr ('"') ; "param"
				invoke lstrcpy,addr buffery,addr LaunchDir
				invoke lstrcat,addr buffery,StrAddr ("\xvi32.exe")
				invoke lstrcat,addr buffery,StrAddr (" ")
				invoke lstrcat,addr buffery,addr bufferx
				lea edi,buffer2
				invoke lstrcpy,edi,addr LaunchDir
				invoke lstrcat,edi,StrAddr ("\Temp\")
				invoke FindFirstChangeNotification,edi,FALSE,FILE_NOTIFY_CHANGE_LAST_WRITE
				push eax
    	        invoke ShowWindow,hWin,SW_MINIMIZE
				invoke CreateProcess,NULL,addr buffery,NULL,NULL,FALSE,\ 
    	              NORMAL_PRIORITY_CLASS,\ 
    	              NULL,NULL,ADDR startInfo,ADDR processInfo
				invoke WaitForSingleObject,processInfo.hProcess,INFINITE
    	        invoke ShowWindow,hWin,SW_RESTORE      
				; check if file changed
				pop eax
				invoke WaitForSingleObject,eax,200
				.if eax==0
					; if changed drop a messagebox "write?"
					; write file
					invoke MessageBox,hWin,StrAddr("File data changed, do you want to write to the phone?"),StrAddr("Warning, data changed!"),MB_YESNO
					.if eax==IDYES
						invoke P2kCopy_up,0,hWin,addr bufferz,hList1
					.endif
				.endif
			.elseif Drive2<4 && LeftRightS==1			
				;p2k edit right
				; 1:download to temp folder buffer=filename
				; dest filename = Launchdir + "\Temp\" + buffer
				invoke lstrcpy,Addr buffery,addr LaunchDir
				invoke lstrcat,Addr buffery,addr Tempdir
				invoke SendMessage,hList2,LVM_GETNEXTITEM,-1,LVNI_SELECTED ;FOCUSED
				mov esi,eax
				invoke P2kCopy_down,esi,hWin,hList2,addr buffery
				invoke lstrcat,addr buffery,addr bufferx ;dest filename+path
				; run xvi32 to view file
				invoke lstrcpy,addr bufferx,StrAddr ('"')
				invoke lstrcat,addr bufferx,addr buffery
				invoke lstrcpy,addr bufferz,addr buffery
				invoke lstrcat,addr bufferx,StrAddr ('"') ; "param"
				invoke lstrcpy,addr buffery,addr LaunchDir
				invoke lstrcat,addr buffery,StrAddr ("\xvi32.exe")
				invoke lstrcat,addr buffery,StrAddr (" ")
				invoke lstrcat,addr buffery,addr bufferx
				lea edi,buffer2
				invoke lstrcpy,edi,addr LaunchDir
				invoke lstrcat,edi,StrAddr ("\Temp\")
				invoke FindFirstChangeNotification,edi,FALSE,FILE_NOTIFY_CHANGE_LAST_WRITE
				push eax
    	        invoke ShowWindow,hWin,SW_MINIMIZE      
				invoke CreateProcess,NULL,addr buffery,NULL,NULL,FALSE,\ 
    	              NORMAL_PRIORITY_CLASS,\ 
    	              NULL,NULL,ADDR startInfo,ADDR processInfo
				invoke WaitForSingleObject,processInfo.hProcess,INFINITE
    	        invoke ShowWindow,hWin,SW_RESTORE      
				; check if file changed
				pop eax
				invoke WaitForSingleObject,eax,200
				.if eax==0
					; if changed drop a messagebox "write?"
					; write file
					invoke MessageBox,hWin,StrAddr("File data changed, do you want to write to the phone?"),StrAddr("Warning, data changed!"),MB_YESNO
					.if eax==IDYES
						invoke P2kCopy_up,0,hWin,addr bufferz,hList2
					.endif
				.endif
			.else
				;local edit
				.if isDir==1
					invoke ShellExecute,hWin,NULL,addr bufferx,NULL,NULL,SW_SHOWDEFAULT
				.else
					invoke lstrcpy,addr buffery,addr LaunchDir
					invoke lstrcat,addr buffery,addr szBackslash
					invoke lstrcat,addr buffery,addr szLister
					invoke ShellExecute,hWin,NULL,addr buffery,addr bufferx,NULL,SW_SHOWDEFAULT
					.if eax<=32 ; error lister not found!
						invoke ShellExecute,hWin,NULL,addr szNotepad,addr bufferx,NULL,SW_SHOWDEFAULT
					.endif
				.endif			
			.endif
;--------------- view ---------------------			
		.elseif eax==IDC_BTN1 ;1007		
		;
		;		invoke CloseHandle,hSMutex
		;
			push LeftRight
			pop LeftRightS
			invoke GetLocalFilename,hWin,-1
			.if Drive1<4 && LeftRightS==0			
			;.if Drive1==0 && LeftRightS==0			
				;p2k view left
				; 1:download to temp folder buffer=filename
				; dest filename = Launchdir + "\Temp\" + buffer
				invoke lstrcpy,Addr buffery,addr LaunchDir
				invoke lstrcat,Addr buffery,addr Tempdir
				invoke SendMessage,hList1,LVM_GETNEXTITEM,-1,LVNI_SELECTED ;FOCUSED
				mov esi,eax
				invoke P2kCopy_down,esi,hWin,hList1,addr buffery
				invoke lstrcat,addr buffery,addr bufferx ;dest filename+path
				invoke ShellExecute,hWin,NULL,addr buffery,NULL,NULL,SW_SHOWDEFAULT
				.if eax==1fh
					invoke lstrcpy,addr bufferx,addr LaunchDir
					invoke lstrcat,addr bufferx,addr szBackslash
					invoke lstrcat,addr bufferx,addr szLister
					invoke ShellExecute,hWin,NULL,addr bufferx,addr buffery,NULL,SW_SHOWDEFAULT
					.if eax<=32 ; error lister not found!
						invoke ShellExecute,hWin,NULL,addr szNotepad,addr buffery,NULL,SW_SHOWDEFAULT
					.endif
				.endif
			.elseif Drive2<4 && LeftRightS==1			
			;.elseif Drive2==0 && LeftRightS==1			
				;p2k view right		
				; 1:download to temp folder buffer=filename
				; dest filename = Launchdir + "\Temp\" + buffer
				invoke lstrcpy,Addr buffery,addr LaunchDir
				invoke lstrcat,Addr buffery,addr Tempdir
				invoke SendMessage,hList2,LVM_GETNEXTITEM,-1,LVNI_SELECTED ;FOCUSED
				mov esi,eax
				invoke P2kCopy_down,esi,hWin,hList2,addr buffery
				invoke lstrcat,addr buffery,addr bufferx ;dest filename+path
				invoke ShellExecute,hWin,NULL,addr buffery,NULL,NULL,SW_SHOWDEFAULT
				.if eax==1fh
					invoke lstrcpy,addr bufferx,addr LaunchDir
					invoke lstrcat,addr bufferx,addr szBackslash
					invoke lstrcat,addr bufferx,addr szLister
					invoke ShellExecute,hWin,NULL,addr bufferx,addr buffery,NULL,SW_SHOWDEFAULT
					.if eax<=32 ; error lister not found!
						invoke ShellExecute,hWin,NULL,addr szNotepad,addr buffery,NULL,SW_SHOWDEFAULT
					.endif
				.endif
			.elseif Drive1==4 && LeftRightS==0
				nop			
			.elseif Drive2==4 && LeftRightS==1
				nop			
			.else
				;local view
				.if isDir==1
					invoke ShellExecute,hWin,NULL,addr bufferx,NULL,NULL,SW_SHOWDEFAULT
				.else
					invoke lstrcpy,addr buffery,addr LaunchDir
					invoke lstrcat,addr buffery,addr szBackslash
					invoke lstrcat,addr buffery,addr szLister
					invoke ShellExecute,hWin,NULL,addr buffery,addr bufferx,NULL,SW_SHOWDEFAULT
					.if eax<=32 ; error lister not found!
						invoke ShellExecute,hWin,NULL,addr szNotepad,addr bufferx,NULL,SW_SHOWDEFAULT
					.endif
				.endif			
			.endif
;-------------- seem func ----------------			
		.elseif eax==IDC_BTN2 ;1004 	;move
			invoke DialogBoxParam,hInstance, 1850,hWin,OFFSET SeemFuncProc,NULL
;------------- delete --------------------		
		.elseif eax==IDC_BTN6 ;1011   	;delete list1/list2 ?
			push LeftRight
			pop LeftRightS
			invoke GetLocalFilename,hWin,-1
			.while eax!=-1
				invoke GetMsgAddr,54
				invoke lstrcpy,addr buffery,eax ;addr szDel
				invoke lstrcat,addr buffery,addr bufferx
				invoke GetMsgAddr,55
				invoke MessageBox,hWin,addr buffery,eax,MB_YESNO
				; execute delete file (name=buffer)
				.if eax==IDYES
					invoke ShowWindow,hList1,SW_HIDE
					invoke ShowWindow,hList2,SW_HIDE
					.if LeftRightS==0 && Drive1>4 ; left panel local drive
					;.if LeftRightS==0 && Drive1!=0 ; left panel local drive
						invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr szDrive1
						invoke SetCurrentDirectory,addr szDrive1
						invoke logstat,addr bufferx
						invoke DeleteFile,addr bufferx
					.elseif LeftRightS==1 && Drive2>4 ; right panel local drive
					;.elseif LeftRightS==1 && Drive2!=0 ; right panel local drive
						invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr szDrive2
						invoke SetCurrentDirectory,addr szDrive2
						invoke logstat,addr bufferx
						invoke DeleteFile,addr bufferx
					.elseif LeftRightS==0 && Drive1<4 ; p2kdrive left
					;.elseif LeftRightS==0 && Drive1==0 ; p2kdrive left
						invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr Fulldir1	; prev path
						mov esi,offset Fulldir1
						mov al,[esi]
						.while al!="/"	;step to first "/" = cut leading "P2k:"
							inc esi
							mov al,[esi]
						.endw
						invoke lstrcat,esi,addr bufferx
                		invoke GetMsgAddr,33
						invoke logstat,eax ;addr str_deleting
						invoke logstat,esi
						push esi ; save filename
						.if isDir==0
							push esi
							call FSAC_delete ; delete works!!!!
							
							pop esi ; get saved filename
							invoke SmartRefreshDel,esi
							
						.else
							push 4
							push esi
							call FSAC_deldir
							
							pop esi ; get saved filename
							invoke SmartRefreshDelDir,esi
							
						.endif
						invoke UpdateStatusBar
						
						;invoke SendDlgItemMessage,hWin,1012,WM_SETFONT,hFontL,TRUE
					.elseif LeftRightS==1 && Drive2<4 ; p2kdrive right
					;.elseif LeftRightS==1 && Drive2==0 ; p2kdrive right
						invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr Fulldir2	; prev path
						mov esi,offset Fulldir2
						mov al,[esi]
						.while al!="/"	;step to first "/" = cut leading "P2k:"
							inc esi
							mov al,[esi]
						.endw
						invoke lstrcat,esi,addr bufferx
                		invoke GetMsgAddr,33
						invoke logstat,eax ;addr str_deleting
						invoke logstat,esi
						push esi ; save filename
						.if isDir==0
							push esi
							call FSAC_delete ; delete works!!!!
							
							pop esi ; get saved filename
							invoke SmartRefreshDel,esi

							
						.else
							push 4
							push esi
							call FSAC_deldir
							
							pop esi ; get saved filename
							invoke SmartRefreshDelDir,esi
							
						.endif	
						invoke UpdateStatusBar	
						;invoke SendDlgItemMessage,hWin,1013,WM_SETFONT,hFontL,TRUE
					.endif
					invoke ShowWindow,hList1,SW_SHOW
					invoke ShowWindow,hList2,SW_SHOW
				.endif
				invoke GetLocalFilename,hWin,CurrentItem
				nop
			.endw	
			; refresh local panels
			.if LeftRightS==0 && Drive1>4
			;.if LeftRightS==0 && Drive1!=0
				invoke FillFileInfo1,hWin
				mov eax,Drive2
				.if eax==Drive1
					invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr szDrive2
					invoke SetCurrentDirectory,addr szDrive2
					invoke FillFileInfo2,hWin
				.endif
				invoke SetFocus,hList1
			.elseif LeftRightS==1 && Drive2>4	
			;.elseif LeftRightS==1 && Drive2!=0	
				invoke FillFileInfo2,hWin
				mov eax,Drive1
				.if eax==Drive2
					invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr szDrive1
					invoke SetCurrentDirectory,addr szDrive1
					invoke FillFileInfo1,hWin
				.endif
				invoke SetFocus,hList2
			.elseif LeftRightS==0 && Drive1<4
			;.elseif LeftRightS==0 && Drive1==0
				invoke P2kGetFileList1,hWin
				invoke SendMessage,hList1,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc1
				invoke UpdatelParam1
			.elseif	LeftRightS==1 && Drive2<4
			;.elseif	LeftRightS==1 && Drive2==0
				invoke P2kGetFileList2,hWin
				invoke SendMessage,hList2,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc2
				invoke UpdatelParam2
			.endif
;--------------------------- copy ---------------------			
		.elseif eax==IDC_BTN24 ;1027    ; copy
			push LeftRight
			pop LeftRightS
			.if Drive1>4 && Drive2>4 ; localcopy
			;.if Drive1!=0 && Drive2!=0 ; localcopy
				invoke GetLocalFilename,hWin,-1
				.while eax!=-1
					invoke lstrcat,addr DestDir,addr szBackslash
					invoke lstrcat,addr DestDir,addr bufferx
					invoke logstat,addr bufferx
					invoke logstat,addr DestDir
					invoke DialogBoxParam,hInstance, 1300,hWin,OFFSET DlgF5Proc,NULL
					nop
					invoke ShowWindow,hList1,SW_HIDE
					invoke ShowWindow,hList2,SW_HIDE
					;execute localcopy
					invoke CopyFile,addr bufferx,addr DestDir,TRUE
					.if eax==0
						invoke GetMsgAddr,56
						invoke lstrcpy,addr buffery,eax ;addr szOvr
						invoke lstrcat,addr buffery,addr bufferx
						invoke ShowWindow,hList1,SW_SHOW
						invoke ShowWindow,hList2,SW_SHOW
						push LeftRight
						invoke GetMsgAddr,57
						invoke MessageBox,hWin,addr buffery,eax,MB_YESNO
						pop LeftRight
						.if eax==IDYES
							invoke ShowWindow,hList1,SW_HIDE
							invoke ShowWindow,hList2,SW_HIDE
							invoke CopyFile,addr bufferx,addr DestDir,FALSE
						.endif
					.endif
					invoke ShowWindow,hList1,SW_SHOW
					invoke ShowWindow,hList2,SW_SHOW
					;pop LeftRight
					invoke GetLocalFilename,hWin,CurrentItem
					nop
				.endw	
				; refresh local destination panel
				.if LeftRightS==0
					invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr szDrive2
					invoke SetCurrentDirectory,addr szDrive2
					invoke FillFileInfo2,hWin
					invoke SetFocus,hList1
				.else	
					invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr szDrive1
					invoke SetCurrentDirectory,addr szDrive1
					invoke FillFileInfo1,hWin
					invoke SetFocus,hList2
				.endif
			.else ; p2k copy up/down
				.if Drive1<4 && Drive2<4			;p2k<---->p2k spec!!!
					.if LeftRight==0
					invoke GetMsgAddr,51
						invoke logstat,eax ;addr szP2kLR
					.else
						invoke GetMsgAddr,52
						invoke logstat,eax ;addr szP2kRL
					.endif
				.elseif LeftRight==0 && Drive1<4	;dload left=p2k right=local
					invoke GetMsgAddr,49
					invoke logstat,eax ;addr szDnLR
					; get source filename
					invoke SendMessage,hList1,LVM_GETNEXTITEM,-1,LVNI_SELECTED ;FOCUSED
					.while eax!=-1
						; do copy task
						invoke P2kCopy_down,eax,hWin,hList1,hList2
						invoke SendMessage,hList1,LVM_GETNEXTITEM,CurrentItem,LVNI_SELECTED ;FOCUSED
					.endw
					; refresh target panel
					invoke SendMessage,hWin,WM_COMMAND,1013,0	
					;
				.elseif LeftRight==1 && Drive2<4 	;dload left=local right=p2k 
					invoke GetMsgAddr,50
					invoke logstat,eax ;addr szDnLR
					; get source filename
					invoke SendMessage,hList2,LVM_GETNEXTITEM,-1,LVNI_SELECTED ;FOCUSED
					.while eax!=-1
						; do copy task
						invoke P2kCopy_down,eax,hWin,hList2,hList1
						invoke SendMessage,hList2,LVM_GETNEXTITEM,CurrentItem,LVNI_SELECTED ;FOCUSED
					.endw
					; refresh target panel
					invoke SendMessage,hWin,WM_COMMAND,1012,0	
					;
				.elseif LeftRight==0 && Drive2<4 	;upload left=local right=p2k 
					invoke GetMsgAddr,47
					invoke logstat,eax ;addr szUpLR
					; get source filename
					invoke SendMessage,hList1,LVM_GETNEXTITEM,-1,LVNI_SELECTED ;FOCUSED
					.while eax!=-1
						; do copy task
						invoke P2kCopy_up,eax,hWin,hList1,hList2
;							mov lvi.iItem,eax
;							mov CurrentItem,eax
;							mov lvi.iSubItem,0
;							mov lvi.imask,LVIF_TEXT
;							lea eax,buffer
;							mov lvi.pszText,eax
;							mov lvi.cchTextMax,256
;							; get the item
;							invoke SendMessage,hList1,LVM_GETITEM,0,addr lvi    ; buffer:filename
;							invoke logstat,addr buffer
;							invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr szDrive1
;							invoke SetCurrentDirectory,addr szDrive1
;							;read file
;							invoke CreateFile,addr buffer,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
;							mov	hReadFile,eax
;							invoke GetFileSize,hReadFile,addr nBytes
;							inc	eax
;							mov	nBytes,eax
;							invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
;							mov	hMemFile,eax
;							invoke ReadFile,hReadFile,hMemFile,nBytes,addr nBytes,FALSE
;							invoke CloseHandle,hReadFile
;							invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr szDrive2
;							mov esi,offset szDrive2
;							mov al,[esi]
;							.while al!="/"	;step to first "/" = cut leading "P2k:"
;								inc esi
;								mov al,[esi]
;							.endw
;							invoke lstrcat,esi,addr buffer
;							
;							invoke lstrcpy,addr bufferx,addr buffer
;							invoke lstrcpy,addr DestDir,esi
;							.if isTargetOverride==1
;								invoke DialogBoxParam,hInstance, 1300,hWin,OFFSET DlgF5Proc,NULL
;							.endif
;							mov esi,offset DestDir
;							push esi ; save name
;	
;							mov NameHW,esi
;							mov AttribHW,eax
;							invoke CreateThread,0,0,addr P2kUploadHW,0,0,0
;							invoke DialogBoxParam,hInstance, 1700,hWin,OFFSET WaitProc,NULL
;							
;							invoke GlobalFree,hMemFile
;							
;							invoke UpdateStatusBar
;							
;							pop esi ;recover saved name
;							invoke SmartRefreshCopy,esi,nBytes,07000400h
							
						invoke SendMessage,hList1,LVM_GETNEXTITEM,CurrentItem,LVNI_SELECTED ;FOCUSED
					.endw
					invoke P2kGetFileList2,hWin
					invoke SendMessage,hList2,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc2
					invoke UpdatelParam2
				.elseif LeftRight==1 && Drive1<4 	;upload left=p2k right=local
					invoke GetMsgAddr,48
					invoke logstat,eax ;addr szUpRL
					; get source filename
					invoke SendMessage,hList2,LVM_GETNEXTITEM,-1,LVNI_SELECTED ;FOCUSED
					.while eax!=-1
						; do copy task
						invoke P2kCopy_up,eax,hWin,hList2,hList1
;							mov lvi.iItem,eax
;							mov CurrentItem,eax
;							mov lvi.iSubItem,0
;							mov lvi.imask,LVIF_TEXT
;							lea eax,buffer
;							mov lvi.pszText,eax
;							mov lvi.cchTextMax,256
;							; get the item
;							invoke SendMessage,hList2,LVM_GETITEM,0,addr lvi    ; buffer:filename
;							invoke logstat,addr buffer
;							invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr szDrive2
;							invoke SetCurrentDirectory,addr szDrive2
;							;read file
;							invoke CreateFile,addr buffer,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
;							mov	hReadFile,eax
;							invoke GetFileSize,hReadFile,addr nBytes
;							inc	eax
;							mov	nBytes,eax
;							invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
;							mov	hMemFile,eax
;							invoke ReadFile,hReadFile,hMemFile,nBytes,addr nBytes,FALSE
;							invoke CloseHandle,hReadFile
;							invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr szDrive1
;							mov esi,offset szDrive1
;							mov al,[esi]
;							.while al!="/"	;step to first "/" = cut leading "P2k:"
;								inc esi
;		
;								mov al,[esi]
;							.endw
;							invoke lstrcat,esi,addr buffer
;							
;							invoke lstrcpy,addr bufferx,addr buffer
;							invoke lstrcpy,addr DestDir,esi
;							.if isTargetOverride==1
;								invoke DialogBoxParam,hInstance, 1300,hWin,OFFSET DlgF5Proc,NULL
;								; DestDir is the target
;							.endif
;							mov esi,offset DestDir
;							push esi ; save name
;							
;							mov NameHW,esi

;							mov AttribHW,eax
;							invoke CreateThread,0,0,addr P2kUploadHW,0,0,0
;							invoke DialogBoxParam,hInstance, 1700,hWin,OFFSET WaitProc,NULL
;							
;							invoke GlobalFree,hMemFile
;							invoke UpdateStatusBar
;							
;							pop esi ;recover saved name
;							invoke SmartRefreshCopy,esi,nBytes,07000400h
;						
						invoke SendMessage,hList2,LVM_GETNEXTITEM,CurrentItem,LVNI_SELECTED ;FOCUSED
					.endw	
					invoke P2kGetFileList1,hWin
					invoke SendMessage,hList1,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc1
					invoke UpdatelParam1
				.elseif LeftRight==0 && Drive1==4 ; seem dload left to right
					; get source filename
					invoke SendMessage,hList1,LVM_GETNEXTITEM,-1,LVNI_SELECTED ;FOCUSED
					.while eax!=-1
						; do copy task
						invoke P2kSeem_down,eax,hWin,hList1,hList2
;						mov lvi.iItem,eax
;						mov CurrentItem,eax
;						mov lvi.iSubItem,0
;						mov lvi.imask,LVIF_TEXT
;						lea eax,buffer
;						mov lvi.pszText,eax
;						mov lvi.cchTextMax,256
;						; get the item
;						invoke SendMessage,hList1,LVM_GETITEM,0,addr lvi    ; buffer:filename
;						invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr szDrive2
;						invoke lstrcpy,addr bufferx,addr szDrive2
;						invoke lstrcat,addr bufferx,addr szBackslash
;						invoke lstrcat,addr bufferx,addr buffer  ; bufferx == target filename to save seem
;						invoke lstrcpy,addr buffery,StrAddr("Download seem: ")
;						invoke lstrcat,addr buffery,addr buffer
;						invoke logstat,addr buffery
;						; read seem
;				        push    offset seem_data
;			            push    0
;			            push    0
;						; get numbers
;						lea esi,buffer
;						mov byte ptr [esi+4],0
;						mov byte ptr [esi+9],0
;						add esi,5
;						invoke htodw,esi ; seem rec
;						push eax
;						sub esi,5
;						invoke htodw,esi ; seem num
;						push eax
;				        ;push    Item
;			            ;push    Seemname
;			            invoke Cmd_RDELEM
;						; save seem
;						invoke DeleteFile,addr bufferx ;savename
;						invoke CreateFile,addr bufferx,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0
;						mov hSaveFile,eax
;						invoke SetFilePointer,hSaveFile,0,0,FILE_BEGIN
;						mov eax,offset seem_data
;						inc eax
;						mov ecx,seem_read_bytes
;						dec ecx
;						invoke WriteFile,hSaveFile,eax,ecx,addr writtenb,0
;						invoke CloseHandle,hSaveFile
						; get next if any	
						invoke SendMessage,hList1,LVM_GETNEXTITEM,CurrentItem,LVNI_SELECTED ;FOCUSED
					.endw
					; refresh target panel
					invoke SendMessage,hWin,WM_COMMAND,1013,0
				.elseif LeftRight==1 && Drive2==4 ; seem dload right to left
					; get source filename
					invoke SendMessage,hList2,LVM_GETNEXTITEM,-1,LVNI_SELECTED ;FOCUSED
					.while eax!=-1
						; do copy task
						invoke P2kSeem_down,eax,hWin,hList2,hList1
;						mov lvi.iItem,eax
;						mov CurrentItem,eax
;						mov lvi.iSubItem,0
;						mov lvi.imask,LVIF_TEXT
;						lea eax,buffer
;						mov lvi.pszText,eax
;						mov lvi.cchTextMax,256
;						; get the item
;						invoke SendMessage,hList2,LVM_GETITEM,0,addr lvi    ; buffer:filename
;						invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr szDrive1
;						invoke lstrcpy,addr bufferx,addr szDrive1
;						invoke lstrcat,addr bufferx,addr szBackslash
;						invoke lstrcat,addr bufferx,addr buffer  ; bufferx == target filename to save seem
;						invoke lstrcpy,addr buffery,StrAddr("Download seem: ")
;						invoke lstrcat,addr buffery,addr buffer
;						invoke logstat,addr buffery
;						; read seem
;				        push    offset seem_data
;			            push    0
;			            push    0
;						; get numbers
;						lea esi,buffer
;						mov byte ptr [esi+4],0
;						mov byte ptr [esi+9],0
;						add esi,5
;						invoke htodw,esi ; seem rec
;						push eax
;						sub esi,5
;						invoke htodw,esi ; seem num
;						push eax
;				        ;push    Item
;			            ;push    Seemname
;			            invoke Cmd_RDELEM
;						; save seem
;						invoke DeleteFile,addr bufferx ;savename
;						invoke CreateFile,addr bufferx,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0
;						mov hSaveFile,eax
;						invoke SetFilePointer,hSaveFile,0,0,FILE_BEGIN
;						mov eax,offset seem_data
;						inc eax
;						mov ecx,seem_read_bytes
;						dec ecx
;						invoke WriteFile,hSaveFile,eax,ecx,addr writtenb,0
;						invoke CloseHandle,hSaveFile
						; get next if any	
						invoke SendMessage,hList2,LVM_GETNEXTITEM,CurrentItem,LVNI_SELECTED ;FOCUSED
					.endw
					; refresh target panel
					invoke SendMessage,hWin,WM_COMMAND,1012,0
				.elseif LeftRight==1 && Drive1==4 ; seem upload right to left
					; get filename

					invoke SendMessage,hList2,LVM_GETNEXTITEM,-1,LVNI_SELECTED ;FOCUSED
					.while eax!=-1
						; do copy task
						invoke P2kSeem_up,eax,hWin,hList2,hList1
;						mov lvi.iItem,eax
;						mov CurrentItem,eax
;						mov lvi.iSubItem,0
;						mov lvi.imask,LVIF_TEXT
;						lea eax,buffer
;						mov lvi.pszText,eax
;
;						mov lvi.cchTextMax,256
;						; get the item
;						invoke SendMessage,hList2,LVM_GETITEM,0,addr lvi    ; buffer:filename
;						invoke lstrcpy,addr buffery,StrAddr("Upload seem: ")
;						invoke lstrcat,addr buffery,addr buffer
;						invoke logstat,addr buffery
;						; check numbers
;						invoke lstrcpy,addr bufferx,addr buffer
;						mov esi,offset bufferx
;						mov byte ptr [esi+4],0
;						mov byte ptr [esi+9],0
;						add esi,5
;						invoke htodw,esi ; seem rec
;						push eax
;						sub esi,5
;						invoke htodw,esi ; seem num
;						pop ebx
;						.if eax>0 && eax<2ffh && ebx>0 && ebx<0ffh
;							push eax
;							push ebx
;							invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr szDrive2
;							invoke SetCurrentDirectory,addr szDrive2
;							;read file
;							invoke CreateFile,addr buffer,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
;							mov	hReadFile,eax
;							invoke GetFileSize,hReadFile,addr nBytes
;							inc	eax
;							mov	nBytes,eax
;							invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
;							mov	hMemFile,eax
;							invoke ReadFile,hReadFile,hMemFile,nBytes,addr nBytes,FALSE
;							invoke CloseHandle,hReadFile
;							; upload seem
;							pop ebx ; rec
;							pop eax ; num
;							push eax
;							push ebx
;				            push    offset seem_data
;				            push    0
;					        push    0
;						    push    ebx ;seem_rec
;				    		push    eax ;seem_num
;				    		invoke Cmd_RDELEM
;				    		pop ebx
;				    		pop eax
;				    		dec     seem_read_bytes
;							push 	hMemFile
;				            push    seem_read_bytes ;bytes=filesize
;					        push    0
;						    push    ebx ;seem_rec
;				    		push    eax ;seem_num
;				    		call Seem_Write
;							
;							invoke GlobalFree,hMemFile
;						.else
;							invoke MessageBox,hWin,StrAddr("Invalid seem filename! Must be: xxxx_yyyy.seem"),StrAddr("Warning!"),MB_OK	
;						.endif	
						; get next if any
						invoke SendMessage,hList2,LVM_GETNEXTITEM,CurrentItem,LVNI_SELECTED ;FOCUSED
					.endw
				.elseif LeftRight==0 && Drive2==4 ; seem upload left to right
					; get filename
					invoke SendMessage,hList1,LVM_GETNEXTITEM,-1,LVNI_SELECTED ;FOCUSED
					.while eax!=-1
						; do copy task
						invoke P2kSeem_up,eax,hWin,hList1,hList2
;						mov lvi.iItem,eax
;						mov CurrentItem,eax
;						mov lvi.iSubItem,0
;						mov lvi.imask,LVIF_TEXT
;
;						lea eax,buffer
;						mov lvi.pszText,eax
;						mov lvi.cchTextMax,256
;						; get the item
;						invoke SendMessage,hList1,LVM_GETITEM,0,addr lvi    ; buffer:filename
;						invoke lstrcpy,addr buffery,StrAddr("Upload seem: ")
;						invoke lstrcat,addr buffery,addr buffer
;						invoke logstat,addr buffery
;						; check numbers
;						invoke lstrcpy,addr bufferx,addr buffer
;						mov esi,offset bufferx
;						mov byte ptr [esi+4],0
;						mov byte ptr [esi+9],0
;						add esi,5
;						invoke htodw,esi ; seem rec
;						push eax
;						sub esi,5
;						invoke htodw,esi ; seem num
;						pop ebx
;						.if eax>0 && eax<2ffh && ebx>0 && ebx<0ffh
;							push eax
;							push ebx
;							invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr szDrive1
;							invoke SetCurrentDirectory,addr szDrive1
;							;read file
;							invoke CreateFile,addr buffer,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
;							mov	hReadFile,eax
;							invoke GetFileSize,hReadFile,addr nBytes
;							inc	eax
;							mov	nBytes,eax
;							invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
;							mov	hMemFile,eax
;							invoke ReadFile,hReadFile,hMemFile,nBytes,addr nBytes,FALSE
;							invoke CloseHandle,hReadFile
;							; upload seem
;							pop ebx ; rec
;							pop eax ; num
;							push eax
;							push ebx
;				            push    offset seem_data
;				            push    0
;					        push    0
;						    push    ebx ;seem_rec
;				    		push    eax ;seem_num
;				    		invoke Cmd_RDELEM
;				    		pop ebx
;				    		pop eax
;				    		dec     seem_read_bytes
;							push 	hMemFile
;				            push    seem_read_bytes ;bytes=filesize
;					        push    0
;						    push    ebx ;seem_rec
;				    		push    eax ;seem_num
;				    		call Seem_Write
;							
;							invoke GlobalFree,hMemFile
;						.else
;							invoke MessageBox,hWin,StrAddr("Invalid seem filename! Must be: xxxx_yyyy.seem"),StrAddr("Warning!"),MB_OK	
;						.endif	
						; get next if any
						invoke SendMessage,hList1,LVM_GETNEXTITEM,CurrentItem,LVNI_SELECTED ;FOCUSED
					.endw
				.endif
			.endif
;------------ makedir -----------------------			
		.elseif eax==IDC_BTN4 ;1009   ; makedir
			invoke DialogBoxParam,hInstance, 1100,hWin,OFFSET DlgF7Proc,NULL
			.if LeftRight==0 && Drive1>4 ; left local
			;.if LeftRight==0 && Drive1!=0 ; left local
				invoke CreateDirectory,addr bufferx,NULL
				invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr szDrive1
				invoke SetCurrentDirectory,addr szDrive1
				invoke FillFileInfo1,hWin
				;invoke SendMessage,hList1,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc1
				;invoke UpdatelParam1
			.elseif LeftRight==1 && Drive2>4 ; right local
			;.elseif LeftRight==1 && Drive2!=0 ; right local
				invoke CreateDirectory,addr bufferx,NULL
				invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr szDrive2
				invoke SetCurrentDirectory,addr szDrive2
				invoke FillFileInfo2,hWin
				;invoke SendMessage,hList2,LVM_SORTITEMS,3,addr CompareFunc2
				;invoke UpdatelParam2
			.elseif LeftRight==0 && Drive1<4 ; p2k drive left
			;.elseif LeftRight==0 && Drive1==0 ; p2k drive left
				invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr Fulldir1	; prev path
				mov esi,offset Fulldir1
				mov al,[esi]
				.while al!="/"	;step to first "/" = cut leading "P2k:"
					inc esi
					mov al,[esi]
				.endw
				invoke lstrcat,esi,addr bufferx
				push esi
				invoke logstat,esi
				push 4h ;04000000h
				push esi
				call FSAC_makedir
				pop esi
				invoke lstrcat,esi,addr szSlash
				invoke lstrcat,esi,addr EmptyDirMark
				push esi ;save name
				;invoke logstat,esi
				push 4  	;attrib
				push esi	;name
				invoke FSAC_open
				push 1  ;filesize
				push offset EmptyDirMarks5vi  ; ptr to file in mem
				invoke FSAC_write
				invoke FSAC_close  
				;invoke SendDlgItemMessage,hWin,1012,WM_SETFONT,hFontL,TRUE
				invoke UpdateStatusBar
						
				pop esi ;recover saved name
				invoke SmartRefreshCopy,esi,1,07000400h
				invoke P2kGetFileList1,hWin
				invoke SendMessage,hList1,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc1
				invoke UpdatelParam1
				
			.elseif LeftRight==1 && Drive2<4
			;.elseif LeftRight==1 && Drive2==0
				invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr Fulldir2	; prev path
				mov esi,offset Fulldir2
				mov al,[esi]
				.while al!="/"	;step to first "/" = cut leading "P2k:"
					inc esi
					mov al,[esi]
				.endw
				invoke lstrcat,esi,addr bufferx
				push esi

				;invoke logstat,esi
				push 4h ;04000000h
				push esi
				call FSAC_makedir
				pop esi
				invoke lstrcat,esi,addr szSlash
				invoke lstrcat,esi,addr EmptyDirMark
				push esi ;save name
				;invoke logstat,esi
				push 4  	;attrib
				push esi	;name
				invoke FSAC_open
				push 1  ;filesize
				push offset EmptyDirMarks5vi  ; ptr to file in mem
				invoke FSAC_write
				invoke FSAC_close  
				;invoke SendDlgItemMessage,hWin,1013,WM_SETFONT,hFontL,TRUE
				invoke UpdateStatusBar
						
				pop esi ;recover saved name
				invoke SmartRefreshCopy,esi,1,07000400h
				invoke P2kGetFileList2,hWin
				invoke SendMessage,hList2,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc2
				invoke UpdatelParam2
				
			.endif		
;---------------- Attrib --------------------			
		.elseif eax==IDC_BTN3 ;1008	
			.if LeftRight==0
				invoke SendMessage,hList1,LVM_GETNEXTITEM,-1,LVNI_SELECTED  ; eax=-1 if no more selected
				.while eax!=-1
					mov lvi.iItem,eax
					mov CurrentItem,eax
					mov PrevPos1,eax
					mov lvi.iSubItem,2
					mov lvi.imask,LVIF_TEXT
					lea eax,bufferx
					mov lvi.pszText,eax
					mov lvi.cchTextMax,256
					; get the item
					invoke SendMessage,hList1,LVM_GETITEM,0,addr lvi    ; buffer:filename
					invoke DialogBoxParam,hInstance, 1400,hWin,OFFSET AttrProc,NULL
					invoke P2kGetFileList1,hWin
					invoke SendMessage,hList1,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc1
					invoke UpdatelParam1
					invoke SendMessage,hList1,LVM_GETNEXTITEM,CurrentItem,LVNI_SELECTED  ; eax=-1 if no more selected
				.endw	
			.else
				invoke SendMessage,hList2,LVM_GETNEXTITEM,-1,LVNI_SELECTED  ; eax=-1 if no more selected
				.while eax!=-1
					mov lvi.iItem,eax
					mov CurrentItem,eax
					mov PrevPos1,eax
					mov lvi.iSubItem,2
					mov lvi.imask,LVIF_TEXT
					lea eax,bufferx
					mov lvi.pszText,eax
					mov lvi.cchTextMax,256
					; get the item
					invoke SendMessage,hList2,LVM_GETITEM,0,addr lvi    ; buffer:filename
					invoke DialogBoxParam,hInstance, 1400,hWin,OFFSET AttrProc,NULL
					invoke P2kGetFileList2,hWin
					invoke SendMessage,hList2,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc2
					invoke UpdatelParam2
					invoke SendMessage,hList2,LVM_GETNEXTITEM,CurrentItem,LVNI_SELECTED  ; eax=-1 if no more selected
				.endw	
			.endif		
;---------------- re-read left panel --------------------			
		.elseif eax==IDC_BTN9 ;1022	; Re-read keyb accel
			.if LeftRight==0
				mov eax,IDC_BTN7
			.else
				mov eax,IDC_BTN8
			.endif
		.endif			
;---------------- re-read left panel --------------------			
		.if eax==IDC_BTN7 ;1012	; Re-read left panel
				.if Drive1<4   ; p2k drive
					.if isUSBLAN==3
						call DevMonitor_ProcLAN
					.else	
						call DevMonitor_Proc
					.endif	
					.if DevFound==1
						invoke GetVolInfo
						invoke SendMessage,hLB1,CB_SETCURSEL,P2kVolume,0
						mov P2kReady,0	
						invoke P2kGetFileList1,hWin
					;	invoke UpdateStatusBar
					.endif	
				.else			; local drive
					mov LeftRight,0
					invoke EnableWindow,hHead1,TRUE
					invoke EnableWindow,hHead2,FALSE
					;invoke SendDlgItemMessage,hWin,1005,CB_RESETCONTENT,0,0
					;invoke GetDrives1
					;invoke SetP2kCB1,hWin
;		invoke GetMsgAddr,116
;		invoke SendDlgItemMessage,hWin,1005,CB_INSERTSTRING,0,eax ;addr P2kPattern ; add p2k drive
;		invoke GetMsgAddr,117
;		invoke SendDlgItemMessage,hWin,1005,CB_INSERTSTRING,1,eax ;addr P2kPattern ; add p2k drive
;		invoke GetMsgAddr,118
;		invoke SendDlgItemMessage,hWin,1005,CB_INSERTSTRING,2,eax ;addr P2kPattern ; add p2k drive
;		invoke GetMsgAddr,119
;		invoke SendDlgItemMessage,hWin,1005,CB_INSERTSTRING,3,eax ;addr P2kPattern ; add p2k drive
;		invoke GetMsgAddr,115 ; seems
;		invoke SendDlgItemMessage,hWin,1005,CB_INSERTSTRING,4,eax ;addr P2kPattern ; add p2k drive
;					invoke SendMessage,hLB1,CB_SETITEMDATA,0,P2kIconIndex
;					invoke SendDlgItemMessage,hWin,1005,CB_SETCURSEL,Drive1,0	
					invoke SetCurrDir1,hWin,Drive1

					.if eax==0   ; no valid drive
						mov Drive1,6  ; c:
						invoke SendDlgItemMessage,hWin,1005,CB_SETCURSEL,Drive1,0	
						invoke SetCurrDir1,hWin,Drive1 
					.endif
					invoke FillFileInfo1,hWin
				.endif
					invoke SendMessage,hList1,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc1
					invoke UpdatelParam1
;-------------- Re-read right panel -------------------				
		.elseif eax==IDC_BTN8 ;1013 ; re-read right panel
			;invoke SendDlgItemMessage,hWin,1013,WM_SETFONT,hFontLo,TRUE
			.if Drive2<4 ; p2k drive
					.if isUSBLAN==3
						call DevMonitor_ProcLAN
					.else	
						call DevMonitor_Proc
					.endif	
					.if DevFound==1	
						invoke GetVolInfo	
						invoke SendMessage,hLB2,CB_SETCURSEL,P2kVolume,0
						mov P2kReady,0	
						invoke P2kGetFileList2,hWin
					;	invoke UpdateStatusBar
					.endif	
			.else      ; local drive
				mov LeftRight,1
				invoke EnableWindow,hHead1,FALSE
				invoke EnableWindow,hHead2,TRUE
				;invoke SendDlgItemMessage,hWin,1006,CB_RESETCONTENT,0,0
				;invoke GetDrives2
				;invoke SetP2kCB2,hWin
;		invoke GetMsgAddr,116
;		invoke SendDlgItemMessage,hWin,1006,CB_INSERTSTRING,0,eax ;addr P2kPattern ; add p2k drive
;		invoke GetMsgAddr,117
;		invoke SendDlgItemMessage,hWin,1006,CB_INSERTSTRING,1,eax ;addr P2kPattern ; add p2k drive
;		invoke GetMsgAddr,118
;		invoke SendDlgItemMessage,hWin,1006,CB_INSERTSTRING,2,eax ;addr P2kPattern ; add p2k drive
;		invoke GetMsgAddr,119
;		invoke SendDlgItemMessage,hWin,1006,CB_INSERTSTRING,3,eax ;addr P2kPattern ; add p2k drive
;		invoke GetMsgAddr,115 ; seems
;		invoke SendDlgItemMessage,hWin,1006,CB_INSERTSTRING,4,eax ;addr P2kPattern ; add p2k drive
;				invoke SendMessage,hLB2,CB_SETITEMDATA,0,P2kIconIndex
;				invoke SendDlgItemMessage,hWin,1006,CB_SETCURSEL,Drive2,0	
				invoke SetCurrDir2,hWin,Drive2
				.if eax==0  ; no valid drive
					mov Drive2,6
					invoke SendDlgItemMessage,hWin,1006,CB_SETCURSEL,Drive2,0	
					invoke SetCurrDir1,hWin,Drive2 
				.endif
				invoke FillFileInfo2,hWin
			.endif
				invoke SendMessage,hList2,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc2
				invoke UpdatelParam2
				;mov FileNameSortOrder,3
			;.endif
;----------------- tab: change left <-> right -----------			
		.elseif eax==IDC_BTN14 ;1020 ;tab
			mov Keytabevent,1
			invoke GetFocus
			;.if LeftRight==0
			.if eax==hList1
				invoke SetFocus,hList2
				mov LeftRight,1
				invoke EnableWindow,hHead1,FALSE
				invoke EnableWindow,hHead2,TRUE
			.else	
				invoke SetFocus,hList1
				mov LeftRight,0
				invoke EnableWindow,hHead1,TRUE
				invoke EnableWindow,hHead2,FALSE
			.endif
;------------- alt F2 : select right panel drive ---------			
		.elseif eax==1019 ;altF2
			invoke SendDlgItemMessage,hWin,1006,CB_SHOWDROPDOWN,TRUE,0
			invoke SetFocus,hLB2
;------------- alt F1 : select left panel drive ---------			
		.elseif eax==1018 ;altF1
			invoke SendDlgItemMessage,hWin,1005,CB_SHOWDROPDOWN,TRUE,0
			invoke SetFocus,hLB1
;------------- F10 : exit ------------------------			
		.elseif eax==1017 ;exit F10
			invoke SendMessage,hWin,WM_CLOSE,0,0
;------------- Backspace : Parentdir ------------------------			
		.elseif eax==1028 ;backspace
			.if LeftRight==0
				invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr bufferx
				invoke lstrlen,addr bufferx
				.if Drive1<4
				;.if Drive1==0
					sub eax,2
				.endif
				.if eax >3
					mov lvi.imask,LVIF_STATE
					mov lvi.iItem,0
					mov lvi.state,LVIS_SELECTED+LVIS_FOCUSED
					mov lvi.stateMask,LVIS_SELECTED+LVIS_FOCUSED
					invoke SendMessage,hList1,LVM_SETITEMSTATE,0,addr lvi
					invoke ShowCurrentFocus1,hWin
				.endif	
			.else	
				invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr bufferx
				invoke lstrlen,addr bufferx
				.if Drive2<4
				;.if Drive2==0
					sub eax,2
				.endif
				.if eax >3
					mov lvi.imask,LVIF_STATE
					mov lvi.iItem,0
					mov lvi.state,LVIS_SELECTED+LVIS_FOCUSED
					mov lvi.stateMask,LVIS_SELECTED+LVIS_FOCUSED
					invoke SendMessage,hList2,LVM_SETITEMSTATE,0,addr lvi
					invoke ShowCurrentFocus2,hWin
				.endif	
			.endif
;------------- INSERT : select item -----------------			
		.elseif eax==1021 ;select INSERT
			invoke SendMessage,hList1,LVM_GETNEXTITEM,-1,LVNI_FOCUSED  ; eax=-1 if no more selected
			mov lvi.imask,LVIF_STATE
			mov lvi.iItem,0
			mov lvi.state,LVIS_SELECTED+LVIS_FOCUSED
			mov lvi.stateMask,LVIS_SELECTED+LVIS_FOCUSED
			mov ebx,eax
			invoke SendMessage,hList1,LVM_SETITEMSTATE,ebx,addr lvi
			inc ebx
			mov lvi.state,LVIS_FOCUSED
			mov lvi.stateMask,LVIS_FOCUSED
			invoke SendMessage,hList1,LVM_SETITEMSTATE,ebx,addr lvi
			nop
;------------- ctlr-alt-5 : usb debug mode -----------------			
		.elseif eax==1029
			.if P2kStatus==1
				invoke DialogBoxParam,hInstance, 1900,hWin,OFFSET USBProc,NULL
				nop
			.endif	
		.endif
;-------------------- select left drive ----------------		
		.if wParam==(CBN_SELENDOK*10000h+IDC_CBO1) ; 1005 select an item from left drive list
			invoke SendDlgItemMessage,hWin,1005,CB_SHOWDROPDOWN,FALSE,0
			mov LeftRight,0
			invoke EnableWindow,hHead1,TRUE
			invoke EnableWindow,hHead2,FALSE
			invoke SendDlgItemMessage,hWin,1005,CB_GETCURSEL,0,0
			mov Drive1,eax
			nop
			.if eax>4    ; local drive
				; set 3. column label  ; fagyi egeres drive selectnél !!!!!!
;				mov lvc.imask,LVCF_TEXT				
;				mov lvc.pszText,offset bufferx
;				mov lvc.cchTextMax,20				
				;invoke SendMessage,hList1,LVM_GETCOLUMN,2,addr lvc
				mov lvc.imask,LVCF_TEXT				
				invoke GetMsgAddr,46
				mov lvc.pszText,eax ;offset Heading4
				invoke SendMessage,hList1,LVM_SETCOLUMN,2,addr lvc
				invoke SendMessage,hList1,LVM_SETCOLUMNWIDTH,0,LVColumn0width
				invoke SendMessage,hList1,LVM_SETCOLUMNWIDTH,2,120
				invoke SetCurrDir1,hWin,Drive1
				nop
				.if eax==0 ; no valid drive
					mov Drive1,6
					invoke SendDlgItemMessage,hWin,1005,CB_SETCURSEL,Drive1,0	
					invoke SetCurrDir1,hWin,Drive1 
				.endif
				invoke FillFileInfo1,hWin
				nop
			.elseif eax<4	; p2k drive
				mov P2kReady,0
				mov P2kVolume,eax
				invoke SendMessage,hLB1,CB_SETCURSEL,P2kVolume,0
;				.if eax==0
;					mov isSlashA,1
;					mov isSlashB,0
;					mov isSlashC,0
;					mov isSlashE,0
;				.elseif eax==1	
;					mov isSlashA,0
;					mov isSlashB,1
;					mov isSlashC,0
;					mov isSlashE,0
;				.elseif eax==2	
;					mov isSlashA,0
;					mov isSlashB,0
;					mov isSlashC,1
;					mov isSlashE,0
;				.elseif eax==3	
;					mov isSlashA,0
;					mov isSlashB,0
;					mov isSlashC,0
;					mov isSlashE,1
;				.endif
				; set 3. column label
				;invoke SendMessage,hList1,LVM_GETCOLUMN,2,addr lvc
				mov lvc.imask,LVCF_TEXT				
				invoke GetMsgAddr,45
				mov lvc.pszText,eax ;offset Heading3
				invoke SendMessage,hList1,LVM_SETCOLUMN,2,addr lvc
				invoke SendMessage,hList1,LVM_SETCOLUMNWIDTH,0,LVColumn0width
				invoke SendMessage,hList1,LVM_SETCOLUMNWIDTH,2,120
				invoke lstrcpy,addr bufferx,addr	szP2kDev  ; "P2k:"
				invoke lstrcat,addr bufferx,addr	P2kDirectory1 ; + actual dir name
				invoke SendDlgItemMessage,hWin,1016,WM_SETTEXT,0,addr bufferx ;szP2kDev
				.if P2kReady==0  ; p2k device not yet read
					mov fromThread,0
					mov fromThread2,0
					.if isUSBLAN==3
						; set filefilter as linux partitions
						invoke SendMessage,hLB1,CB_GETLBTEXT,P2kVolume,addr FileFilter
						invoke logstat,StrAddr ("Reading filesystem from:")
						invoke logstat,addr FileFilter
						call DevMonitor_ProcLAN
					.else	
						call DevMonitor_Proc
					.endif	
					.if DevFound==1 
						;push eax
						invoke GetVolInfo
						invoke SendMessage,hLB1,CB_SETCURSEL,P2kVolume,0
						; filelistat kesziteni /a/dummyfile /b/dummyfile 
						; invoke
						.if Files_found !=0 || isCDMA==1 
							invoke P2kGetFileList1,hWin
						.endif	
						; buffer végére tenni
						;	mov esi,offset cdummy
						;	invoke SmartRefreshCopy,esi,nBytes,07000400h
						;invoke P2kGetFileList1,hWin
					.endif	
				.else	
					invoke P2kGetFileList1,hWin
					nop
				.endif
			.elseif eax==4 ;&& isP2k05==0 ; seem
				;
				; seem list into file panel
				;
				mov P2kReady,0
				mov P2kVolume,eax
				invoke SendMessage,hLB1,CB_SETCURSEL,P2kVolume,0
				mov lvc.imask,LVCF_TEXT				
				invoke GetMsgAddr,126
				mov lvc.pszText,eax ;offset Heading4
				invoke SendMessage,hList1,LVM_SETCOLUMN,2,addr lvc
				invoke SendMessage,hList1,LVM_SETCOLUMNWIDTH,0,132
				mov ebx,LVColumn0width
				sub ebx,132
				add ebx,120
				invoke SendMessage,hList1,LVM_SETCOLUMNWIDTH,2,ebx
				invoke P2kGetSeemList1,hWin
				mov isSeemRoot,1
			.endif
				invoke SendMessage,hList1,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc1
				invoke UpdatelParam1
		.endif	
;-------------------- select right drive ----------------		
		.if wParam==(CBN_SELENDOK*10000h+IDC_CBO2)	; select an item from right drive list
			invoke SendDlgItemMessage,hWin,1006,CB_SHOWDROPDOWN,FALSE,0
			mov LeftRight,1
			invoke EnableWindow,hHead1,FALSE
			invoke EnableWindow,hHead2,TRUE
			invoke SendDlgItemMessage,hWin,1006,CB_GETCURSEL,0,0
			mov Drive2,eax
			.if eax>4	; local drive
				; set 3. column label
				;invoke SendMessage,hList2,LVM_GETCOLUMN,2,addr lvc
				mov lvc.imask,LVCF_TEXT				
				invoke GetMsgAddr,46
				mov lvc.pszText,eax ;offset Heading4
				invoke SendMessage,hList2,LVM_SETCOLUMN,2,addr lvc
				invoke SendMessage,hList2,LVM_SETCOLUMNWIDTH,0,LVColumn0width
				invoke SendMessage,hList2,LVM_SETCOLUMNWIDTH,2,120
				invoke SetCurrDir2,hWin,Drive2
				.if eax==0  ; no valid drive
					mov Drive2,6
					invoke SendDlgItemMessage,hWin,1006,CB_SETCURSEL,Drive2,0	
					invoke SetCurrDir1,hWin,Drive2 
				.endif
				invoke FillFileInfo2,hWin
			.elseif eax<4   ; p2k drive
				mov P2kReady,0
				mov P2kVolume,eax
				invoke SendMessage,hLB2,CB_SETCURSEL,P2kVolume,0
				; set 3. column label
				;invoke SendMessage,hList2,LVM_GETCOLUMN,2,addr lvc
				mov lvc.imask,LVCF_TEXT				
				invoke GetMsgAddr,45
				mov lvc.pszText,eax ;offset Heading3
				invoke SendMessage,hList2,LVM_SETCOLUMN,2,addr lvc
				invoke SendMessage,hList2,LVM_SETCOLUMNWIDTH,0,LVColumn0width
				invoke SendMessage,hList2,LVM_SETCOLUMNWIDTH,2,120
				invoke lstrcpy,addr bufferx,addr	szP2kDev	; "P2k:"
				invoke lstrcat,addr bufferx,addr	P2kDirectory2	; + actual dir anme
				invoke SendDlgItemMessage,hWin,1015,WM_SETTEXT,0,addr bufferx ;szP2kDev
				.if P2kReady==0  ; p2k device not yet read
					mov fromThread,0
					mov fromThread2,0
					.if isUSBLAN==3
						; set filefilter as linux partitions
						invoke SendMessage,hLB2,CB_GETLBTEXT,P2kVolume,addr FileFilter
						invoke logstat,StrAddr ("Reading filesystem from:")
						invoke logstat,addr FileFilter
						call DevMonitor_ProcLAN
					.else	
						call DevMonitor_Proc
					.endif	
					.if DevFound==1
						;push eax
						invoke GetVolInfo
						invoke SendMessage,hLB2,CB_SETCURSEL,P2kVolume,0
						.if Files_found !=0 
							invoke P2kGetFileList2,hWin
						.endif	
					.endif	
				.else	
					invoke P2kGetFileList2,hWin
				.endif
			.elseif eax==4 ;&& isP2k05==0 ; seem
				;
				; seem list into file panel
				;
				mov P2kReady,0
				mov P2kVolume,eax
				invoke SendMessage,hLB2,CB_SETCURSEL,P2kVolume,0
				mov lvc.imask,LVCF_TEXT				
				invoke GetMsgAddr,126
				mov lvc.pszText,eax ;offset Heading4
				invoke SendMessage,hList2,LVM_SETCOLUMN,2,addr lvc
				invoke SendMessage,hList2,LVM_SETCOLUMNWIDTH,0,132
				mov ebx,LVColumn0width
				sub ebx,132
				add ebx,120
				invoke SendMessage,hList2,LVM_SETCOLUMNWIDTH,2,ebx
				invoke P2kGetSeemList2,hWin
				mov isSeemRoot,1
			.endif	
				invoke SendMessage,hList2,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc2
				invoke UpdatelParam2
		.elseif wParam==(EN_KILLFOCUS*10000h+1016) ; path edittext loses focus 
			invoke SendMessage,hHead1,EM_UNDO,0,0
			invoke SendMessage,hHead1,EM_EMPTYUNDOBUFFER,0,0
		.elseif wParam==(EN_KILLFOCUS*10000h+1015)
			invoke SendMessage,hHead2,EM_UNDO,0,0
			invoke SendMessage,hHead2,EM_EMPTYUNDOBUFFER,0,0
		.endif
;------------------ resize windows -----------------------
	.elseif eax==WM_SIZE
		.if wParam==SIZE_MAXIMIZED
			invoke GetWindowRect,hWin,addr Wrect
			mov lParam,offset Wrect
			mov eax,WM_SIZING
		.endif	
		.if wParam==SIZE_RESTORED
			invoke GetWindowRect,hWin,addr Wrect
			invoke ComputeLayout,hWin
;			invoke GetWindowRect,hWin,addr Wrect
;			invoke GetWindowPlacement,hList1,addr ListPlacement1
;			invoke GetWindowPlacement,hList2,addr ListPlacement2
;			invoke GetWindowPlacement,hHead1,addr DirPlacement1
;			invoke GetWindowPlacement,hHead2,addr DirPlacement2
;			invoke GetWindowPlacement,hLB2,addr LBPlacement2
;			invoke GetWindowPlacement,hReread2,addr RereadPlacement2
;
;			mov eax,Wrect.right
;			sub eax,Wrect.left
;			mov ebx,ListPlacement1.rcNormalPosition.right
;			sub ebx,ListPlacement1.rcNormalPosition.left
;			sub eax,ebx
;			.if  CARRY? || eax<225 
;				mov eax,Wrect.right
;				sub eax,Wrect.left
;				sub eax,225
;				mov ListPlacement1.rcNormalPosition.right,eax
;				mov DirPlacement1.rcNormalPosition.right,eax
;				add eax,4
;				mov ListPlacement2.rcNormalPosition.left,eax
;				mov DirPlacement2.rcNormalPosition.left,eax
;				mov LBPlacement2.rcNormalPosition.left,eax
;				add eax,134
;				mov LBPlacement2.rcNormalPosition.right,eax
;				inc eax
;				mov RereadPlacement2.rcNormalPosition.left,eax
;				add eax,75
;				mov RereadPlacement2.rcNormalPosition.right,eax
;				invoke SetWindowPlacement,hList1,addr ListPlacement1
;				invoke SetWindowPlacement,hList2,addr ListPlacement2
;				invoke SetWindowPlacement,hHead1,addr DirPlacement1
;				invoke SetWindowPlacement,hHead2,addr DirPlacement2
;				invoke SetWindowPlacement,hLB2,addr LBPlacement2
;				invoke SetWindowPlacement,hReread2,addr RereadPlacement2
;			.endif
;;			pop eax
;;			.if  eax<208
;;				nop
;;			.endif
;			invoke SendMessage,hWin,WM_SIZING,wParam,offset Wrect			
;			;mov lParam,offset Wrect
;			;mov eax,WM_SIZING
		.endif	
	.endif	
	.if eax==WM_SIZING
		push esi
		invoke LockWindowUpdate,hWin ;less flickering
		invoke LockWindowUpdate,hList1
		invoke LockWindowUpdate,hList2
		invoke LockWindowUpdate,hF2
		invoke LockWindowUpdate,hF3
		invoke LockWindowUpdate,hF4
		invoke LockWindowUpdate,hF5
		invoke LockWindowUpdate,hF6
		invoke LockWindowUpdate,hF7
		invoke LockWindowUpdate,hF8
		invoke LockWindowUpdate,hF9
		invoke LockWindowUpdate,hHead1
		invoke LockWindowUpdate,hHead2
		invoke LockWindowUpdate,hReread2
		invoke LockWindowUpdate,hLB2
		invoke LockWindowUpdate,hBar
		invoke LockWindowUpdate,hLog
;		invoke LockWindowUpdate,hSplitter
		invoke GetWindowPlacement,hList1,addr ListPlacement1
		invoke GetWindowPlacement,hList2,addr ListPlacement2
		invoke GetWindowPlacement,hHead1,addr DirPlacement1
		invoke GetWindowPlacement,hHead2,addr DirPlacement2
		invoke GetWindowPlacement,hReread2,addr RereadPlacement2
		invoke GetWindowPlacement,hLB2,addr LBPlacement2
		invoke GetWindowPlacement,hF2,addr F2Placement
		invoke GetWindowPlacement,hF3,addr F3Placement
		invoke GetWindowPlacement,hF4,addr F4Placement
		invoke GetWindowPlacement,hF5,addr F5Placement
		invoke GetWindowPlacement,hF6,addr F6Placement
		invoke GetWindowPlacement,hF7,addr F7Placement
		invoke GetWindowPlacement,hF8,addr F8Placement
		invoke GetWindowPlacement,hF9,addr F9Placement
		invoke GetWindowPlacement,hBar,addr BarPlacement
		invoke GetWindowPlacement,hLog,addr LogPlacement
		invoke GetWindowPlacement,hStatus,addr StatPlacement
;		invoke GetWindowPlacement,hSplitter,addr SplitterPlacement
		; horizontal settings
		mov esi,lParam
		assume esi:ptr RECT
		mov eax,[esi].right
		sub eax,[esi].left
		sub eax,8 ;10		; -border -distance
		push eax
		sub eax,2		
		mov ListPlacement2.rcNormalPosition.right,eax
		mov DirPlacement2.rcNormalPosition.right,eax
		;sub eax,2
		mov BarPlacement.rcNormalPosition.right,eax
		pop eax
		shr eax,1		; /2
		push eax
		push eax
		sub eax,0 ;2		
			mov ListPlacement1.rcNormalPosition.right,eax
			mov DirPlacement1.rcNormalPosition.right,eax
		mov LogPlacement.rcNormalPosition.right,eax
		pop eax 
		add eax,2
			mov ListPlacement2.rcNormalPosition.left,eax
		;sub eax,3
			mov DirPlacement2.rcNormalPosition.left,eax
			mov LBPlacement2.rcNormalPosition.left,eax
		add eax,1 ;3
		mov BarPlacement.rcNormalPosition.left,eax
		mov F3Placement.rcNormalPosition.left,eax
		mov F6Placement.rcNormalPosition.left,eax
		add eax,64+70+20
			mov LBPlacement2.rcNormalPosition.right,eax
		add eax,1 ;3
		;add eax,91
			mov RereadPlacement2.rcNormalPosition.left,eax
		;sub eax,91	
		sub eax,3
		add eax,27-70-24+16 ;button widht=100px
		mov F3Placement.rcNormalPosition.right,eax
		mov F6Placement.rcNormalPosition.right,eax
		add eax,1 ;4
		mov F4Placement.rcNormalPosition.left,eax
		mov F5Placement.rcNormalPosition.left,eax
		add eax,36+8+70+24 
		;add eax,91
			mov RereadPlacement2.rcNormalPosition.right,eax
		;sub eax,91	
		add eax,58-8-70-24-24+30
		mov F4Placement.rcNormalPosition.right,eax
		mov F5Placement.rcNormalPosition.right,eax
		add eax,1 ;4
		mov F2Placement.rcNormalPosition.left,eax
		mov F7Placement.rcNormalPosition.left,eax
		add eax,100 ;94
		mov F2Placement.rcNormalPosition.right,eax
		mov F7Placement.rcNormalPosition.right,eax
		add eax,1 ;4
		mov F9Placement.rcNormalPosition.left,eax
		mov F8Placement.rcNormalPosition.left,eax
		add eax,100 ;70
		mov F9Placement.rcNormalPosition.right,eax
		mov F8Placement.rcNormalPosition.right,eax
		; vertical settings
		mov eax,[esi].bottom
		sub eax,[esi].top
		sub eax,141
		mov ListPlacement1.rcNormalPosition.bottom,eax
		mov ListPlacement2.rcNormalPosition.bottom,eax
		add eax,2
		mov LogPlacement.rcNormalPosition.top,eax
		mov F3Placement.rcNormalPosition.top,eax
		mov F4Placement.rcNormalPosition.top,eax
		mov F2Placement.rcNormalPosition.top,eax
		mov F9Placement.rcNormalPosition.top,eax
		add eax,30
		mov F3Placement.rcNormalPosition.bottom,eax
		mov F4Placement.rcNormalPosition.bottom,eax
		mov F2Placement.rcNormalPosition.bottom,eax
		mov F9Placement.rcNormalPosition.bottom,eax
		mov F6Placement.rcNormalPosition.top,eax
		mov F5Placement.rcNormalPosition.top,eax
		mov F7Placement.rcNormalPosition.top,eax
		mov F8Placement.rcNormalPosition.top,eax
		add eax,30
		mov F6Placement.rcNormalPosition.bottom,eax
		mov F5Placement.rcNormalPosition.bottom,eax
		mov F7Placement.rcNormalPosition.bottom,eax
		mov F8Placement.rcNormalPosition.bottom,eax
		add eax,6	
		mov BarPlacement.rcNormalPosition.top,eax
		add eax,23-6-23
		mov LogPlacement.rcNormalPosition.bottom,eax
		add eax,23
		mov BarPlacement.rcNormalPosition.bottom,eax
		add eax,3
		mov StatPlacement.rcNormalPosition.bottom,eax
		
		invoke SetWindowPlacement,hList1,addr ListPlacement1
		invoke SetWindowPlacement,hList2,addr ListPlacement2
		invoke SetWindowPlacement,hHead2,addr DirPlacement2
		invoke SetWindowPlacement,hHead1,addr DirPlacement1
		invoke SetWindowPlacement,hLB2,addr LBPlacement2
		invoke SetWindowPlacement,hReread2,addr RereadPlacement2
		invoke SetWindowPlacement,hF2,addr F2Placement
		invoke SetWindowPlacement,hF3,addr F3Placement
		invoke SetWindowPlacement,hF4,addr F4Placement
		invoke SetWindowPlacement,hF5,addr F5Placement
		invoke SetWindowPlacement,hF6,addr F6Placement
		invoke SetWindowPlacement,hF7,addr F7Placement
		invoke SetWindowPlacement,hF8,addr F8Placement
		invoke SetWindowPlacement,hF9,addr F9Placement
		invoke SetWindowPlacement,hBar,addr BarPlacement
		invoke SetWindowPlacement,hLog,addr LogPlacement
		invoke SetWindowPlacement,hStatus,addr StatPlacement
;		invoke SetWindowPlacement,hSplitter,addr SplitterPlacement
		; set hover values
		mov eax,ListPlacement1.rcNormalPosition.bottom
		mov LVHoverSizeY,eax
		sub eax,200
		mov LVOriginalSizeY,eax
		mov eax,LogPlacement.rcNormalPosition.top
		mov LBOriginalSizeY,eax 
		sub eax,200
		mov LBHoverSizeY,eax
		assume esi:nothing
		invoke LockWindowUpdate,NULL
		pop ebx
		.if ebx>344
			sub ebx,344
			add ebx,132
			mov LVColumn0width,ebx
			.if Drive1==4
				mov ebx,132
				invoke SendMessage,hList1,LVM_SETCOLUMNWIDTH,0,ebx
			.else	
				invoke SendMessage,hList1,LVM_SETCOLUMNWIDTH,0,ebx
			.endif
			.if Drive2==4
				mov ebx,132	
				invoke SendMessage,hList2,LVM_SETCOLUMNWIDTH,0,ebx
			.else	
				invoke SendMessage,hList2,LVM_SETCOLUMNWIDTH,0,ebx
			.endif	
		.elseif ebx<343
			mov ebx,132
			invoke SendMessage,hList1,LVM_SETCOLUMNWIDTH,0,ebx
			invoke SendMessage,hList2,LVM_SETCOLUMNWIDTH,0,ebx
		.endif
		pop esi


		
		
;---------------------- listview, and other notifications -------------		
	.elseif uMsg==WM_NOTIFY
		push edi
		mov edi,lParam
		assume edi:ptr NMHDR
		mov eax,[edi].hwndFrom
		.if eax==hList1
			.if Keytabevent==0
				invoke EnableWindow,hHead1,TRUE
				invoke EnableWindow,hHead2,FALSE
				.if Drive1<4
				;.if Drive1==0
					invoke EnableWindow,hF2,TRUE
					invoke EnableWindow,hF3,TRUE
					invoke EnableWindow,hF7,TRUE
					invoke EnableWindow,hF8,TRUE
					;invoke EnableWindow,hF4,FALSE
		            ;INVOKE     EnableMenuItem, hRMenu,2, MF_GRAYED + MF_BYPOSITION
        		    INVOKE     EnableMenuItem, hRMenu,1, MF_GRAYED + MF_BYPOSITION					
        		    INVOKE     EnableMenuItem, hRMenu,0, MF_ENABLED + MF_BYPOSITION					
        		    INVOKE     EnableMenuItem, hRMenu,5, MF_ENABLED + MF_BYPOSITION					
        		    INVOKE     EnableMenuItem, hRMenu,6, MF_ENABLED + MF_BYPOSITION					
				.elseif Drive1==4 ; seem	
					invoke EnableWindow,hF7,FALSE
					invoke EnableWindow,hF8,FALSE
        		    INVOKE     EnableMenuItem, hRMenu,5, MF_GRAYED + MF_BYPOSITION					
        		    INVOKE     EnableMenuItem, hRMenu,6, MF_GRAYED + MF_BYPOSITION					
				.else	
					invoke EnableWindow,hF2,FALSE
					invoke EnableWindow,hF3,TRUE
					invoke EnableWindow,hF7,TRUE
					invoke EnableWindow,hF4,TRUE
					;invoke EnableWindow,hF8,TRUE
		            ;INVOKE     EnableMenuItem, hRMenu,2, MF_ENABLED + MF_BYPOSITION
        		    INVOKE     EnableMenuItem, hRMenu,1, MF_ENABLED + MF_BYPOSITION					
        		    INVOKE     EnableMenuItem, hRMenu,5, MF_ENABLED + MF_BYPOSITION					
        		    INVOKE     EnableMenuItem, hRMenu,0, MF_GRAYED + MF_BYPOSITION					
        		    INVOKE     EnableMenuItem, hRMenu,6, MF_ENABLED + MF_BYPOSITION					
				.endif
			.endif		
			mov LeftRight,0
			.if [edi].code==LVN_BEGINDRAG  ; initiate drag'n drop
				nop
;			.elseif [edi].code==NM_CUSTOMDRAW  ; coloured rows
;	            assume edi:ptr NMLVCUSTOMDRAW
;               .if [edi].nmcd.dwDrawStage == CDDS_PREPAINT
;                  mov eax,CDRF_NOTIFYITEMDRAW
;                  ret
;               .elseif [edi].nmcd.dwDrawStage == CDDS_ITEMPREPAINT 
;    		      ;;;;;;;do stuff in this section              
;                  .if [edi].nmcd.lItemlParam == 8
;			           MOV [EDI].clrText,00ffh   ;red text
;			           MOV [EDI].clrTextBk,0ff0000h   ;blue text background
;                  .endif
;            	  ;;;;;;;stop doing crap
;			      assume edi:ptr NMHDR
;                  mov eax, CDRF_NEWFONT
;                  ret
;               .endif
			.elseif [edi].code==LVN_ITEMACTIVATE  ; mouse dblclick or keyboard enter
				invoke ShowCurrentFocus1,hWin ; on dir = change dir
				mov Keytabevent,0
			.elseif [edi].code==LVN_COLUMNCLICK   ; sort columns
				assume edi:ptr NM_LISTVIEW				
				.if [edi].iSubItem==1
					.if SizeSortOrder==0 || SizeSortOrder==2
						invoke SendMessage,hList1,LVM_SORTITEMS,1,addr CompareFunc1
						invoke UpdatelParam1
						mov SizeSortOrder,1
						mov hdi.iImage,2
						invoke SendMessage,hLVHeader1,HDM_SETITEM,1,ADDR hdi
						mov hdi.iImage,0
						invoke SendMessage,hLVHeader1,HDM_SETITEM,0,ADDR hdi
					.else
						invoke SendMessage,hList1,LVM_SORTITEMS,2,addr CompareFunc1
						invoke UpdatelParam1
						mov SizeSortOrder,2
						mov hdi.iImage,1
						invoke SendMessage,hLVHeader1,HDM_SETITEM,1,ADDR hdi
						mov hdi.iImage,0
						invoke SendMessage,hLVHeader1,HDM_SETITEM,0,ADDR hdi
					.endif					
				.elseif [edi].iSubItem==0
					.if FileNameSortOrder==0 || FileNameSortOrder==4
						invoke SendMessage,hList1,LVM_SORTITEMS,3,addr CompareFunc1
						invoke UpdatelParam1
						mov FileNameSortOrder,3
						mov hdi.iImage,2
						invoke SendMessage,hLVHeader1,HDM_SETITEM,0,ADDR hdi
						mov hdi.iImage,0
						invoke SendMessage,hLVHeader1,HDM_SETITEM,1,ADDR hdi
					.else
						invoke SendMessage,hList1,LVM_SORTITEMS,4,addr CompareFunc1
						invoke UpdatelParam1
						mov FileNameSortOrder,4
						mov hdi.iImage,1
						invoke SendMessage,hLVHeader1,HDM_SETITEM,0,ADDR hdi
						mov hdi.iImage,0
						invoke SendMessage,hLVHeader1,HDM_SETITEM,1,ADDR hdi
					.endif										
				.endif
			assume edi:ptr NMHDR
			.elseif [edi].code==LVN_KEYDOWN
				mov esi,lParam
				assume esi:ptr LV_KEYDOWN
				;mov edi,[esi].hdr
				mov word ptr ax,[esi].wVKey   ; insert key==2dh
				nop
				assume esi:NOTHING
			.elseif [edi].code==NM_DBLCLK
				;invoke ShowCurrentFocus1,hWin
			.endif
		.elseif	eax==hList2
			.if Keytabevent==0
				invoke EnableWindow,hHead1,FALSE
				invoke EnableWindow,hHead2,TRUE
				.if Drive2<4
				;.if Drive2==0
					invoke EnableWindow,hF2,TRUE
					invoke EnableWindow,hF3,TRUE
					invoke EnableWindow,hF4,FALSE
		            INVOKE     EnableMenuItem, hRMenu,2, MF_GRAYED + MF_BYPOSITION
        		    INVOKE     EnableMenuItem, hRMenu,1, MF_GRAYED + MF_BYPOSITION					
        		    INVOKE     EnableMenuItem, hRMenu,0, MF_ENABLED + MF_BYPOSITION					
				.else	
					invoke EnableWindow,hF2,FALSE
					invoke EnableWindow,hF3,TRUE
					invoke EnableWindow,hF4,TRUE
		            INVOKE     EnableMenuItem, hRMenu,2, MF_ENABLED + MF_BYPOSITION
        		    INVOKE     EnableMenuItem, hRMenu,1, MF_ENABLED + MF_BYPOSITION					

        		    INVOKE     EnableMenuItem, hRMenu,0, MF_GRAYED + MF_BYPOSITION					
				.endif
			.endif		
			mov LeftRight,1
			.if [edi].code==LVN_ITEMACTIVATE	; mouse dblclick or keyboard enter
				invoke ShowCurrentFocus2,hWin	; on dir = change dir
				mov Keytabevent,0
			.elseif [edi].code==LVN_COLUMNCLICK		; sort columns
				assume edi:ptr NM_LISTVIEW				
				.if [edi].iSubItem==1
					.if SizeSortOrder==0 || SizeSortOrder==2
						invoke SendMessage,hList2,LVM_SORTITEMS,1,addr CompareFunc2
						invoke UpdatelParam2
						mov SizeSortOrder,1
						mov hdi.iImage,2
						invoke SendMessage,hLVHeader2,HDM_SETITEM,1,ADDR hdi
						mov hdi.iImage,0
						invoke SendMessage,hLVHeader2,HDM_SETITEM,0,ADDR hdi
					.else
						invoke SendMessage,hList2,LVM_SORTITEMS,2,addr CompareFunc2
						invoke UpdatelParam2
						mov SizeSortOrder,2
						mov hdi.iImage,1
						invoke SendMessage,hLVHeader2,HDM_SETITEM,1,ADDR hdi
						mov hdi.iImage,0
						invoke SendMessage,hLVHeader2,HDM_SETITEM,0,ADDR hdi
					.endif					
				.elseif [edi].iSubItem==0
					.if FileNameSortOrder==0 || FileNameSortOrder==4
						invoke SendMessage,hList2,LVM_SORTITEMS,3,addr CompareFunc2
						invoke UpdatelParam2
						mov FileNameSortOrder,3
						mov hdi.iImage,2
						invoke SendMessage,hLVHeader2,HDM_SETITEM,0,ADDR hdi
						mov hdi.iImage,0
						invoke SendMessage,hLVHeader2,HDM_SETITEM,1,ADDR hdi
					.else
						invoke SendMessage,hList2,LVM_SORTITEMS,4,addr CompareFunc2
						invoke UpdatelParam2
						mov FileNameSortOrder,4
						mov hdi.iImage,1
						invoke SendMessage,hLVHeader2,HDM_SETITEM,0,ADDR hdi
						mov hdi.iImage,0
						invoke SendMessage,hLVHeader2,HDM_SETITEM,1,ADDR hdi
					.endif										
				.endif
			;assume edi:ptr NMHDR
			;.elseif [edi].code==NM_DBLCLK
			;	invoke ShowCurrentFocus2,hWin
			.endif


		.endif
		assume edi:nothing
		pop edi
	.elseif eax==WM_CLOSE
		invoke SaveConfig,hWin
		;invoke SaveLog,hWin
			.if isUSBLAN==1
				mov startInfo.wShowWindow,SW_HIDE
				invoke CreateProcess,NULL,addr CmdSambaOff,NULL,NULL,FALSE,\ 
		              NORMAL_PRIORITY_CLASS,\ 
		              NULL,NULL,ADDR startInfo,ADDR processInfo
				mov startInfo.wShowWindow,SW_SHOW
			.elseif isUSBLAN==2
				;
				; Stop ftpdive
				;
				invoke TerminateProcess,FtpDrivePID,0
				nop
			.elseif isUSBLAN==3
				;
				; Close Socket
				;
				.if hSocket!=INVALID_SOCKET
					invoke closesocket, hSocket
				.endif
				;
				; Cleanup Winsock2
				;
				invoke  WSACleanup
			.endif
;		.if isFade==1 ;OSVer.dwMajorVersion>4
;			mov eax,LayeredSave
;			invoke SetWindowLongA,hWin,GWL_EXSTYLE,eax
;			mov TransTimer,255
;			invoke SetLayeredWindowAttributes,hWin,0,TransTimer,2   ; LWA_ALPHA = 2
;			;invoke UpdateLayeredWindow,hWin,0,0,0,0,0,0,addr Blendfunction,2
;			invoke UpdateWindow,hWin
;			.while TransTimer>5
;				dec TransTimer
;				dec TransTimer
;				dec TransTimer
;				dec TransTimer
;				dec TransTimer
;				dec TransTimer
;				dec TransTimer
;				dec TransTimer
;				dec TransTimer
;				dec TransTimer
;				invoke Sleep,20
;				invoke SetLayeredWindowAttributes,hWin,0,TransTimer,2   ; LWA_ALPHA = 2
;			.endw
;		.endif	
;			mov eax,LayeredSave
;			invoke SetWindowLongA,hWin,GWL_EXSTYLE,eax
		invoke DeleteObject,hBrushDwm
		invoke DeleteObject,hBackgr
		invoke DestroyWindow,hWin
		.if SearchBuf_Ptr!=0
			invoke GlobalFree,SearchBuf_Ptr
		.endif	
		; free lang file mem
		invoke GlobalFree,hMemLang
		invoke GlobalFree,hMemLangPtrs
		; free seem file mem
		invoke GlobalFree,hMemSeem
		invoke GlobalFree,hMemSeemPtrs
		invoke GlobalFree,hMemSeemF
		invoke GlobalFree,hMemSeemFPtrs
		.if hMemHiddenF!=0
			invoke GlobalFree,hMemHiddenF
			invoke GlobalFree,hMemHiddenFPtrs
		.endif
;		invoke KillTimer,hWin,TimerID
;		invoke KillTimer,hWin,ScanTimerID
	.elseif uMsg==WM_DESTROY
		invoke PostQuitMessage,NULL
	.else
		invoke DefWindowProc,hWin,uMsg,wParam,lParam
		ret
	.endif
	xor    eax,eax
	ret

WndProc endp
;
; Left and right ListView init procedure
;
InsertColumn proc
	LOCAL lvc:LV_COLUMN 
	LOCAL sfi:SHFILEINFO
    mov     eax, LVS_EX_FULLROWSELECT or LVS_EX_HEADERDRAGDROP or\
                      LVS_EX_SUBITEMIMAGES or LVS_EX_GRIDLINES or LVS_EX_LABELTIP
    push eax
    INVOKE     SendMessage, hList1, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, eax
    pop eax
    INVOKE     SendMessage, hList2, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, eax
    
    ; imagelist create for listview
    ;INVOKE     ImageList_Create, 16, 16, ILC_COLOR32, 3, 0
    INVOKE     SHGetFileInfo, addr szRootPath, 0, addr sfi, sizeof SHFILEINFO,\
                 SHGFI_SYSICONINDEX or SHGFI_SMALLICON
    mov     hImageListS, eax
    INVOKE     SendMessage, hList1, LVM_SETIMAGELIST, LVSIL_SMALL, hImageListS
    INVOKE     SendMessage, hList2, LVM_SETIMAGELIST, LVSIL_SMALL, hImageListS

	mov lvc.imask,LVCF_TEXT+LVCF_WIDTH
	invoke GetMsgAddr,43
	mov lvc.pszText,eax ;offset Heading1
	mov lvc.lx,140
	invoke SendMessage,hList1, LVM_INSERTCOLUMN,0,addr lvc
	or lvc.imask,LVCF_FMT
	mov lvc.fmt,LVCFMT_RIGHT
	invoke GetMsgAddr,44
	mov lvc.pszText,eax ;offset Heading2
	mov lvc.lx,68
	invoke SendMessage,hList1, LVM_INSERTCOLUMN, 1 ,addr lvc	
	invoke GetMsgAddr,46
	mov lvc.pszText,eax ;offset Heading4
	mov lvc.lx,120
	mov lvc.fmt,LVCFMT_LEFT
	invoke SendMessage,hList1, LVM_INSERTCOLUMN, 2 ,addr lvc	

	mov lvc.imask,LVCF_TEXT+LVCF_WIDTH
	invoke GetMsgAddr,43
	mov lvc.pszText,eax ;offset Heading1
	mov lvc.lx,140
	invoke SendMessage,hList2, LVM_INSERTCOLUMN,0,addr lvc
	or lvc.imask,LVCF_FMT
	mov lvc.fmt,LVCFMT_RIGHT
	invoke GetMsgAddr,44
	mov lvc.pszText,eax ;offset Heading2
	mov lvc.lx,68
	invoke SendMessage,hList2, LVM_INSERTCOLUMN, 1 ,addr lvc
	invoke GetMsgAddr,46
	mov lvc.pszText,eax ;offset Heading4
	mov lvc.lx,120
	mov lvc.fmt,LVCFMT_LEFT
	invoke SendMessage,hList2, LVM_INSERTCOLUMN, 2 ,addr lvc	
		;
		; set up listview headers
		;
		invoke SendMessage,hList1,LVM_GETHEADER,0,0
		mov hLVHeader1,eax
		invoke SendMessage,hList2,LVM_GETHEADER,0,0
		mov hLVHeader2,eax
		invoke ImageList_LoadImage,hInstance,5000,16,0,08000FFh,IMAGE_BITMAP,LR_CREATEDIBSECTION
		mov hLVHImagelist,eax
		push eax
		invoke SendMessage,hLVHeader1,HDM_SETIMAGELIST,0,eax
		pop eax
		invoke SendMessage,hLVHeader2,HDM_SETIMAGELIST,0,eax
		mov hdi.imask,HDI_FORMAT + HDI_IMAGE
		mov hdi.fmt,HDF_IMAGE + HDF_STRING + HDF_BITMAP_ON_RIGHT
		mov hdi.iImage,0
		invoke SendMessage,hLVHeader1,HDM_SETITEM,1,ADDR hdi
		invoke SendMessage,hLVHeader1,HDM_SETITEM,2,ADDR hdi
		invoke SendMessage,hLVHeader2,HDM_SETITEM,1,ADDR hdi
		invoke SendMessage,hLVHeader2,HDM_SETITEM,2,ADDR hdi
		mov hdi.iImage,2
		invoke SendMessage,hLVHeader1,HDM_SETITEM,0,ADDR hdi
		invoke SendMessage,hLVHeader2,HDM_SETITEM,0,ADDR hdi
	ret
InsertColumn endp
;
; Left: insert 1 row to listview lpFind = found file address
; local filesystem
;
ShowFileInfo1 proc uses esi edi row:DWORD, lpFind:DWORD
	LOCAL lvi:LV_ITEM
	LOCAL buffer[256]:BYTE
	LOCAL sfi:SHFILEINFO
;	LOCAL    Lft:FILETIME
;	LOCAL    time:SYSTEMTIME
	push esi
	mov edi,lpFind
	assume edi:ptr WIN32_FIND_DATA
    test [edi].dwFileAttributes,FILE_ATTRIBUTE_DIRECTORY 
    .if !ZERO?
		mov isDir,1       	
	.else
		mov isDir,0	
    .endif
    mov lvi.imask, LVIF_TEXT or LVIF_IMAGE or LVIF_PARAM
	push row
	pop lvi.iItem	
	mov lvi.iSubItem,0
	lea eax,[edi].cFileName
	push eax
	mov lvi.pszText,eax
	push row
	pop lvi.lParam
	; get image for file
	invoke lstrcpy,addr bufferx,eax
	
	mov esi,eax
	.if word ptr [esi]!="."
	
	    INVOKE     SHGetFileInfo, addr bufferx, 0, addr sfi, sizeof SHFILEINFO,SHGFI_SYSICONINDEX or SHGFI_SMALLICON or SHGFI_TYPENAME or SHGFI_ATTRIBUTES
	    mov hSystemImageList,eax
	    mov     eax, sfi.iIcon
	    mov     lvi.iImage, eax
	    ; insert filename    
		invoke SendMessage,hList1, LVM_INSERTITEM,0, addr lvi
		mov lvi.imask,LVIF_TEXT
		inc lvi.iSubItem
		invoke wsprintf,addr buffer, addr template,[edi].nFileSizeLow
		lea eax,buffer
		mov lvi.pszText,eax
		pop eax
		mov ax,[eax]
		.if isDir==1
			invoke lstrcpy,lvi.pszText,addr szDirMark
			mov isDir,0
		.endif
		; insert filesize or "< DIR >"
		invoke SendMessage,hList1,LVM_SETITEM, 0,addr lvi
		; insert filedate
		mov lvi.imask,LVIF_TEXT
		inc lvi.iSubItem
;---------- [Get the time] ----------
        INVOKE     FileTimeToLocalFileTime,addr [edi].ftLastWriteTime, addr Lft
        INVOKE     FileTimeToSystemTime,addr Lft, addr time
        invoke GetDateFormat,NULL,NULL,addr time,NULL,addr bufferx,255
        invoke GetTimeFormat,NULL,NULL,addr time,addr TimeFormat,addr buffery,255
        invoke lstrcat,addr bufferx,addr buffery
        lea     eax, bufferx ;cdt.dyr
        mov     lvi.pszText, eax
	    INVOKE     SendMessage, hList1, LVM_SETITEM, 0, addr lvi
		inc row
	.endif
	mov eax,row	
	assume edi:nothing
	pop esi
	ret
ShowFileInfo1 endp
;
; Right: insert 1 row to listview lpFind = found file address
; local filesystem
;
ShowFileInfo2 proc uses esi edi row:DWORD, lpFind:DWORD
	LOCAL lvi:LV_ITEM
	LOCAL buffer[256]:BYTE
	LOCAL sfi:SHFILEINFO
	
	mov edi,lpFind
	assume edi:ptr WIN32_FIND_DATA
    test [edi].dwFileAttributes,FILE_ATTRIBUTE_DIRECTORY 
    .if !ZERO?
		mov isDir,1       	
	.else
		mov isDir,0	
    .endif
    mov lvi.imask, LVIF_TEXT or LVIF_IMAGE or LVIF_PARAM
	push row
	pop lvi.iItem	
	mov lvi.iSubItem,0
	lea eax,[edi].cFileName
	push eax
	mov lvi.pszText,eax
	push row
	pop lvi.lParam
	; get image for file
	invoke lstrcpy,addr bufferx,eax

	mov esi,eax
	.if word ptr [esi]!="."
	
	    INVOKE     SHGetFileInfo, addr bufferx, 0, addr sfi, sizeof SHFILEINFO,\
	                SHGFI_SYSICONINDEX or SHGFI_SMALLICON or SHGFI_TYPENAME or SHGFI_ATTRIBUTES
	    mov     eax, sfi.iIcon
	    mov     lvi.iImage, eax

	    ; insert filename    
		invoke SendMessage,hList2, LVM_INSERTITEM,0, addr lvi
		mov lvi.imask,LVIF_TEXT
		inc lvi.iSubItem
		invoke wsprintf,addr buffer, addr template,[edi].nFileSizeLow
		lea eax,buffer
		mov lvi.pszText,eax
		pop eax
		mov ax,[eax]
		.if isDir==1 
			invoke lstrcpy,lvi.pszText,addr szDirMark
			mov isDir,0
		.endif
		; insert filesize or "< DIR >"
		invoke SendMessage,hList2,LVM_SETITEM, 0,addr lvi
		; insert filedate
		mov lvi.imask,LVIF_TEXT
		inc lvi.iSubItem
;---------- [Get the time] ----------
        INVOKE     FileTimeToLocalFileTime,addr [edi].ftLastWriteTime, addr Lft
        INVOKE     FileTimeToSystemTime,addr Lft, addr time
        invoke GetDateFormat,NULL,NULL,addr time,NULL,addr bufferx,255
        invoke GetTimeFormat,NULL,NULL,addr time,addr TimeFormat,addr buffery,255
        invoke lstrcat,addr bufferx,addr buffery
        lea     eax, bufferx ;cdt.dyr
        mov     lvi.pszText, eax
	    INVOKE     SendMessage, hList2, LVM_SETITEM, 0, addr lvi
		inc row
	.endif
	mov eax,row	
	assume edi:nothing
	ret
ShowFileInfo2 endp
;
; Fill Left listview with all file
; local filesystem
;
FillFileInfo1 proc uses esi hWin:HWND
	LOCAL finddata:WIN32_FIND_DATA
	LOCAL FHandle2:DWORD
	LOCAL lvi:LV_ITEM
	LOCAL sfi:SHFILEINFO
	LOCAL buffer[256]:BYTE

	invoke LockWindowUpdate,hList1
	invoke SendMessage,hList1,LVM_DELETEALLITEMS,0,0
;			; put ".."
;		    mov lvi.imask, LVIF_TEXT or LVIF_IMAGE or LVIF_PARAM
;			mov lvi.iItem,0	
;			mov lvi.iSubItem,0
;			lea eax,offset szParentdir
;			mov lvi.pszText,eax
;			mov lvi.lParam,0
;	        INVOKE SHGetFileInfo,lvi.pszText, 0, addr sfi, sizeof SHFILEINFO,SHGFI_SYSICONINDEX or SHGFI_SMALLICON or SHGFI_TYPENAME or SHGFI_ATTRIBUTES
;	        mov     eax,sfi.iIcon
;		    mov     lvi.iImage, eax
;			invoke SendMessage,hList1, LVM_INSERTITEM,0, addr lvi
;			mov lvi.imask,LVIF_TEXT
;			inc lvi.iSubItem
;			invoke lstrcpy,addr buffer,addr szDirMark
;			lea eax,buffer
;			mov lvi.pszText,eax
;			invoke SendMessage,hList1,LVM_SETITEM, 0,addr lvi
	invoke FindFirstFile,addr FileNamePattern,addr finddata ; *.* = all files
		        ;INVOKE     FileTimeToSystemTime,addr finddata.ftLastAccessTime, addr time
		        ;INVOKE     fmtime, time.SYSTEMTIME
		        ;mov edi,offset cdt.dmo
		        ;mov eax,[edi]
		        ;mov ebx,[edi+4]
		        ;mov ecx,[edi+8]
		        ;mov edx,[edi+12]
	.if eax!=INVALID_HANDLE_VALUE
		mov FHandle2,eax
		xor esi,esi
		.while eax!=0  ; there are more files
				invoke ShowFileInfo1,esi, addr finddata
				mov esi,eax  ;inc edi
			invoke FindNextFile,FHandle2,addr finddata
		.endw
		invoke LockWindowUpdate,NULL
		invoke FindClose,FHandle2
	.endif
	invoke SendMessage,hList1,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc1
	invoke UpdatelParam1
	ret
FillFileInfo1 endp
;
; Fill Right listview with all file
; local filesystem
;
FillFileInfo2 proc uses edi hWin:HWND
	LOCAL finddata:WIN32_FIND_DATA
	LOCAL FHandle2:DWORD

	invoke LockWindowUpdate,hList2
	invoke SendMessage,hList2,LVM_DELETEALLITEMS,0,0
	
	invoke FindFirstFile,addr FileNamePattern,addr finddata
	.if eax!=INVALID_HANDLE_VALUE
		mov FHandle2,eax
		xor edi,edi
		.while eax!=0	; there are more files
				invoke ShowFileInfo2,edi, addr finddata
				mov edi,eax ;inc edi
			invoke FindNextFile,FHandle2,addr finddata
		.endw
		invoke LockWindowUpdate,NULL
		invoke FindClose,FHandle2
	.endif
	invoke SendMessage,hList2,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc2
	invoke UpdatelParam2
	ret
FillFileInfo2 endp

String2Dword proc uses ecx edi edx esi String:DWORD
	LOCAL Result:DWORD
	mov Result,0
        mov edi,String
        invoke lstrlen,String
        .while eax!=0
                xor edx,edx
                mov dl,byte ptr [edi]
                sub dl,"0"      ; subtrack each digit with "0" to convert it to hex value
                mov esi,eax
                dec esi
                push eax
                mov eax,edx
                push ebx
                mov ebx,10
                .while esi > 0
                        mul ebx
                        dec esi
                .endw
                pop ebx
                add Result,eax
                pop eax
                inc edi
                dec eax
        .endw
        mov eax,Result
        ret
String2Dword endp
;
; This needed for listview sorting (left panel)
;
CompareFunc1 proc uses edi esi ebx  lParam1:DWORD, lParam2:DWORD, SortType:DWORD
	LOCAL buffer[256]:BYTE
	LOCAL buffer1[256]:BYTE
	LOCAL lvi:LV_ITEM
	mov lvi.imask,LVIF_TEXT or LVIF_IMAGE
	lea eax,buffer
	mov lvi.pszText,eax
	mov lvi.cchTextMax,256
	mov lvi.iSubItem,1
	invoke SendMessage,hList1,LVM_GETITEMTEXT,lParam1,addr lvi
	mov esi,lvi.pszText
	mov al,byte ptr [esi]
	push eax
	mov lvi.iSubItem,1
	invoke SendMessage,hList1,LVM_GETITEMTEXT,lParam2,addr lvi
	pop eax
	; Make directory entries on the top
	mov esi,lvi.pszText
	mov ah,byte ptr [esi]
	.if al=="<" && ah!="<" 	  ; dir
			mov eax,-1
			ret
	.elseif ah=="<" && al!="<"
			mov eax,1
			ret
	.elseif al=="<" && ah=="<"
	; Make parentdir on the top
		push bx
		mov lvi.iSubItem,0
		invoke SendMessage,hList1,LVM_GETITEMTEXT,lParam1,addr lvi
		mov esi,lvi.pszText
		mov ax,word ptr [esi]
		push eax
		mov lvi.iSubItem,0
		invoke SendMessage,hList1,LVM_GETITEMTEXT,lParam2,addr lvi
		pop eax
		mov esi,lvi.pszText
		mov bx,word ptr [esi]
		.if ax==".."
			pop bx
			mov eax,-1
			ret
		.elseif bx==".."
			pop bx
			mov eax,1
			ret
		.endif	
		pop bx	


	.endif
	.if SortType==1		; Numeric sorting 
		mov lvi.iSubItem,1	;filesize
		invoke SendMessage,hList1,LVM_GETITEMTEXT,lParam1,addr lvi
		invoke String2Dword,addr buffer
		mov edi,eax
		invoke SendMessage,hList1,LVM_GETITEMTEXT,lParam2,addr lvi
		invoke String2Dword,addr buffer
		sub edi,eax
		mov eax,edi
	.elseif SortType==2	; Numeric sorting
		mov lvi.iSubItem,1	;filesize
		invoke SendMessage,hList1,LVM_GETITEMTEXT,lParam1,addr lvi
		invoke String2Dword,addr buffer
		mov edi,eax
		invoke SendMessage,hList1,LVM_GETITEMTEXT,lParam2,addr lvi
		invoke String2Dword,addr buffer
		sub eax,edi
	.elseif SortType==3		; alpha sorting	
		mov lvi.iSubItem,0	; filename
		invoke SendMessage,hList1,LVM_GETITEMTEXT,lParam1,addr lvi
       	invoke lstrcpy,addr buffer1,addr buffer
		invoke SendMessage,hList1,LVM_GETITEMTEXT,lParam2,addr lvi
		invoke lstrcmpi,addr buffer1,addr buffer		
	.else
		mov lvi.iSubItem,0	; alpha sorting, filename
		invoke SendMessage,hList1,LVM_GETITEMTEXT,lParam1,addr lvi
		invoke lstrcpy,addr buffer1,addr buffer
		invoke SendMessage,hList1,LVM_GETITEMTEXT,lParam2,addr lvi
		invoke lstrcmpi,addr buffer,addr buffer1
	.endif
	ret
CompareFunc1 endp
;
; This needed for listview sorting (right panel)
;
CompareFunc2 proc uses esi edi ebx lParam1:DWORD, lParam2:DWORD, SortType:DWORD
	LOCAL buffer[256]:BYTE
	LOCAL buffer1[256]:BYTE
	LOCAL lvi:LV_ITEM
	mov lvi.imask,LVIF_TEXT
	lea eax,buffer
	mov lvi.pszText,eax
	mov lvi.cchTextMax,256
	mov lvi.iSubItem,1
	invoke SendMessage,hList2,LVM_GETITEMTEXT,lParam1,addr lvi
	mov esi,lvi.pszText
	mov al,byte ptr [esi]
	push eax
	mov lvi.iSubItem,1
	invoke SendMessage,hList2,LVM_GETITEMTEXT,lParam2,addr lvi
	pop eax
	; Make directory entries on the top
	mov esi,lvi.pszText
	mov ah,byte ptr [esi]
	.if al=="<" && ah!="<" 	  ; dir
			mov eax,-1
			ret
	.elseif ah=="<" && al!="<"
			mov eax,1
			ret
	.elseif al=="<" && ah=="<"
	; Make parentdir on the top
		push bx
		mov lvi.iSubItem,0
		invoke SendMessage,hList2,LVM_GETITEMTEXT,lParam1,addr lvi
		mov esi,lvi.pszText
		mov ax,word ptr [esi]
		push eax
		mov lvi.iSubItem,0
		invoke SendMessage,hList2,LVM_GETITEMTEXT,lParam2,addr lvi
		pop eax
		mov esi,lvi.pszText
		mov bx,word ptr [esi]
		.if ax==".."
			pop bx
			mov eax,-1
			ret
		.elseif bx==".."
			pop bx
			mov eax,1
			ret
		.endif	
		pop bx	
	.endif
	.if SortType==1	; Numeric sorting
		mov lvi.iSubItem,1	;filesize
		invoke SendMessage,hList2,LVM_GETITEMTEXT,lParam1,addr lvi
		invoke String2Dword,addr buffer
		mov edi,eax
		invoke SendMessage,hList2,LVM_GETITEMTEXT,lParam2,addr lvi
		invoke String2Dword,addr buffer
		sub edi,eax
		mov eax,edi
	.elseif SortType==2	; Numeric sorting
		mov lvi.iSubItem,1	;filesize
		invoke SendMessage,hList2,LVM_GETITEMTEXT,lParam1,addr lvi
		invoke String2Dword,addr buffer
		mov edi,eax
		invoke SendMessage,hList2,LVM_GETITEMTEXT,lParam2,addr lvi
		invoke String2Dword,addr buffer
		sub eax,edi
	.elseif SortType==3	; alpha sorting
		mov lvi.iSubItem,0	; filename
		invoke SendMessage,hList2,LVM_GETITEMTEXT,lParam1,addr lvi
		invoke lstrcpy,addr buffer1,addr buffer
		invoke SendMessage,hList2,LVM_GETITEMTEXT,lParam2,addr lvi
		invoke lstrcmpi,addr buffer1,addr buffer		
	.else
		mov lvi.iSubItem,0	; alpha sorting ; filename
		invoke SendMessage,hList2,LVM_GETITEMTEXT,lParam1,addr lvi
		invoke lstrcpy,addr buffer1,addr buffer
		invoke SendMessage,hList2,LVM_GETITEMTEXT,lParam2,addr lvi
		invoke lstrcmpi,addr buffer,addr buffer1
	.endif
	ret
CompareFunc2 endp
;
; After sorting this needed to re-compute lParam indexes (Left panel)
;
UpdatelParam1 proc uses edi
	LOCAL lvi:LV_ITEM
	invoke SendMessage,hList1, LVM_GETITEMCOUNT,0,0
	mov edi,eax
	mov lvi.imask,LVIF_PARAM
	mov lvi.iSubItem,0
	mov lvi.iItem,0
	.while edi>0
		push lvi.iItem
		pop lvi.lParam
		invoke SendMessage,hList1, LVM_SETITEM,0,addr lvi
		inc lvi.iItem
		dec edi
	.endw
	invoke SelectFirst1,PrevPos1
	ret
UpdatelParam1 endp
;
; After sorting this needed to re-compute lParam indexes (Right panel)
;
UpdatelParam2 proc uses edi
	LOCAL lvi:LV_ITEM
	invoke SendMessage,hList2, LVM_GETITEMCOUNT,0,0
	mov edi,eax
	mov lvi.imask,LVIF_PARAM
	mov lvi.iSubItem,0
	mov lvi.iItem,0
	.while edi>0
		push lvi.iItem
		pop lvi.lParam
		invoke SendMessage,hList2, LVM_SETITEM,0,addr lvi
		inc lvi.iItem
		dec edi
	.endw
	invoke SelectFirst2,PrevPos2
	ret
UpdatelParam2 endp
;
; Activating a listview entry (on dir = change directory) Left panel
;
ShowCurrentFocus1 proc uses esi ecx hWin:DWORD ; dir change on enter key
	LOCAL lvi:LV_ITEM
	LOCAL buffer[256]:BYTE
	LOCAL buffer2[256]:BYTE
	LOCAL Row:DWORD
	LOCAL sfi:SHFILEINFO
	LOCAL Seemname:DWORD
	LOCAL Item:DWORD
;	LOCAL startInfo:STARTUPINFO
	
	invoke SendMessage,hList1,LVM_GETNEXTITEM,-1,LVNI_FOCUSED
	mov lvi.iItem,eax
	push eax
	mov lvi.iSubItem,1 ;*0
	mov lvi.imask,LVIF_TEXT
	lea eax,buffer
	mov lvi.pszText,eax
	mov lvi.cchTextMax,256
	; get the item
	invoke SendMessage,hList1,LVM_GETITEM,0,addr lvi    ; buffer:filename
	lea eax,buffer
	.if byte ptr [eax]=="<"
		mov isDir,1 
	.else	
		mov isDir,0 
	.endif
	mov lvi.iSubItem,0
	pop lvi.iItem
	mov lvi.imask,LVIF_TEXT
	lea eax,buffer
	mov lvi.pszText,eax
	mov lvi.cchTextMax,256
	invoke SendMessage,hList1,LVM_GETITEM,0,addr lvi    ; buffer:filename
	
	lea esi,buffer
	mov ax,[esi]
	.if ax==".."
		mov isUpDir,1
	.else
		mov isUpDir,0
	.endif
	.if Drive1>4  ; local filesystem
	;.if Drive1!=0  ; local filesystem
		invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr Fulldir1 ; prev path
		invoke lstrcat,addr Fulldir1,addr szBackslash 	; add "\"
		invoke lstrcat,addr Fulldir1,addr buffer		; add "new dir" (even if it is "..")
		invoke SetCurrentDirectory,addr Fulldir1 		; set new dir
		.if eax==0  ; error this is file, not dir
			; execute file (start associated app)
			invoke ShellExecute,hWin,NULL,addr buffer,NULL,NULL,SW_SHOWDEFAULT
		.else
			invoke GetCurrentDirectory,255,addr Fulldir1	; get new dir
			invoke SendDlgItemMessage,hWin,1016,WM_SETTEXT,0,addr Fulldir1
			invoke FillFileInfo1,hWin	; update listview with files of new dir
		;	.if isUpDir==1 
		;		invoke SelectFirst1,PrevPos1
		;	.else	
		;		invoke SelectFirst1,0
		;		;mov eax,lvi.iItem
		;		;mov PrevPos1,eax
		;	.endif
		.endif
	.elseif Drive1==4  ;p2k seemroot
		.if isSeemRoot==1
			invoke lstrcat,addr Fulldir1,esi
			invoke SendDlgItemMessage,hWin,1016,WM_SETTEXT,0,addr Fulldir1 
			; set seem name
			invoke lstrcpy,addr phone_model,esi
			invoke htodw,esi
			mov Seemname,eax
			mov isSeemRoot,0
			invoke SendMessage,hList1,LVM_DELETEALLITEMS,0,0
			mov Row,0
			; put ".."
		    mov lvi.imask, LVIF_TEXT or LVIF_IMAGE or LVIF_PARAM
			push Row
			pop lvi.iItem	
			mov lvi.iSubItem,0
			lea eax,offset szParentdir
			mov lvi.pszText,eax
			push Row
			pop lvi.lParam
	        INVOKE SHGetFileInfo,lvi.pszText, 0, addr sfi, sizeof SHFILEINFO,SHGFI_SYSICONINDEX or SHGFI_SMALLICON or SHGFI_TYPENAME or SHGFI_ATTRIBUTES
	        mov     eax,sfi.iIcon
		    mov     lvi.iImage, eax
			invoke SendMessage,hList1, LVM_INSERTITEM,0, addr lvi
			mov lvi.imask,LVIF_TEXT
			inc lvi.iSubItem
			invoke lstrcpy,addr buffer,addr szDirMark
			lea eax,buffer
			mov lvi.pszText,eax
			invoke SendMessage,hList1,LVM_SETITEM, 0,addr lvi
			; get list of records
			mov Item,0
			mov eax,0ffh
			inc eax
			shl eax,16
			invoke SendMessage,hBar,PBM_SETRANGE,0,eax
			invoke SendMessage,hBar,PBM_SETSTEP,1,0
			invoke SendMessage,hBar,PBM_SETPOS,0,0
			invoke LockWindowUpdate,hList1
			.while Item!=0ffh 
				inc Item
				inc Row
		        push    offset seem_data2
	            push    0
	            push    0
		        push    Item
	            push    Seemname
	            mov stay_quiet,1
	            invoke Cmd_RDELEM
	            mov stay_quiet,0
	            .if eax==0
					mov esi,offset phone_model
					add esi,4
					mov byte ptr [esi],"_"
					inc esi
					invoke dw2ah,Item,esi
					mov eax,[esi+4]
					mov [esi],eax
					mov dword ptr [esi+4],'ees.'
					mov byte ptr [esi+4+4],'m'
					mov byte ptr [esi+4+5],0
					sub esi,5
					push esi
					; add item to hList1
					; get image for file
					invoke lstrcpy,addr buffery,addr LaunchDir
					invoke lstrcat,addr buffery,addr Templates
					invoke lstrcat,addr buffery,StrAddr("_.seem")
				    mov lvi.imask, LVIF_TEXT or LVIF_IMAGE or LVIF_PARAM
					push Row
					pop lvi.iItem	
					mov lvi.iSubItem,0
					pop lvi.pszText
					push Row
					pop lvi.lParam
			        INVOKE     SHGetFileInfo,addr buffery, 0, addr sfi, sizeof SHFILEINFO,SHGFI_SYSICONINDEX
			        .if eax==0
			        	mov eax,UnknownIcon
			        	mov sfi.iIcon,eax
			        .endif
			        mov     eax,sfi.iIcon
			        mov     lvi.iImage, eax
					invoke SendMessage,hList1, LVM_INSERTITEM,0, addr lvi
;					; get size
;			        push    offset seem_data
;		            push    0
;		            push    0
;			        push    Item
;		            push    Seemname
;		            invoke Cmd_RDELEM
		            mov eax,seem_read_bytes
		            dec eax
		            lea esi,buffer
		            invoke dwtoa,eax,esi
		            mov lvi.pszText,esi
					inc lvi.iSubItem
					mov lvi.imask,LVIF_TEXT
					invoke SendMessage,hList1,LVM_SETITEM, 0,addr lvi
					dec lvi.iSubItem
				.else 
					mov	Item,0ffh	
					invoke SendMessage,hBar,PBM_SETPOS,0ffh,0
	            .endif
				invoke SendDlgItemMessage,hWin,1014,PBM_STEPIT,0,0
			.endw
			invoke LockWindowUpdate,NULL
		.else
			; check if ".." and go root
			.if isUpDir==1
				invoke P2kGetSeemList1,hWin
				mov isSeemRoot,1
			.else
				; download to /Temp
				; read seem
		        push    offset seem_data
	            push    0
	            push    0
				; get numbers
				;lea esi,buffer
				mov byte ptr [esi+4],0
				mov byte ptr [esi+9],0
				add esi,5
				invoke htodw,esi ; seem rec
				push eax
				sub esi,5
				invoke htodw,esi ; seem num
				push eax
		        ;push    Item
	            ;push    Seemname
	            invoke Cmd_RDELEM
				; save seem
				invoke lstrcpy,addr bufferx,addr LaunchDir
				invoke lstrcat,addr bufferx,StrAddr ("\Temp\")
				lea esi,buffer
				mov byte ptr [esi+4],"_"
				mov byte ptr [esi+9],"."
				invoke lstrcat,addr bufferx,esi
				invoke DeleteFile,addr bufferx ;savename
				invoke CreateFile,addr bufferx,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0
				mov hSaveFile,eax
				invoke SetFilePointer,hSaveFile,0,0,FILE_BEGIN
				mov eax,offset seem_data
				inc eax
				mov ecx,seem_read_bytes
				dec ecx
				invoke WriteFile,hSaveFile,eax,ecx,addr writtenb,0
				invoke CloseHandle,hSaveFile
				; run xvi32 to view seem
				invoke lstrcpy,addr bufferx,addr LaunchDir
				invoke lstrcat,addr bufferx,StrAddr ("\xvi32.exe")
				invoke lstrcpy,addr buffery,StrAddr ('"')
				invoke lstrcat,addr buffery,addr LaunchDir
				invoke lstrcat,addr buffery,StrAddr ("\Temp\")
				invoke lstrcat,addr buffery,esi
				invoke lstrcat,addr buffery,StrAddr ('"')
				
				invoke lstrcat,addr bufferx,StrAddr (" ")
				invoke lstrcat,addr bufferx,addr buffery
				
				lea edi,buffer2
				invoke lstrcpy,edi,addr LaunchDir
				invoke lstrcat,edi,StrAddr ("\Temp\")
				invoke FindFirstChangeNotification,edi,FALSE,FILE_NOTIFY_CHANGE_LAST_WRITE
				;invoke logstat,addr buffery
				push eax
    	        invoke ShowWindow,hWin,SW_MINIMIZE      
				invoke CreateProcess,NULL,addr bufferx,NULL,NULL,FALSE,\ 
    	              NORMAL_PRIORITY_CLASS,\ 
    	              NULL,NULL,ADDR startInfo,ADDR processInfo
				invoke WaitForSingleObject,processInfo.hProcess,INFINITE
    	        invoke ShowWindow,hWin,SW_RESTORE      
				; check if file changed
				pop eax
				invoke WaitForSingleObject,eax,200
				.if eax==0
					; if changed drop a messagebox "write?"
					; write seem
					invoke MessageBox,hWin,StrAddr("Seem data changed, do you want to write to the phone?"),StrAddr("Warning, data changed!"),MB_YESNO
					.if eax==IDYES
						; write seem file
						lea esi,buffer
						invoke lstrcpy,addr buffery,addr LaunchDir
						invoke lstrcat,addr buffery,StrAddr ("\Temp\")
						invoke lstrcat,addr buffery,esi
						;invoke logstat
						mov byte ptr [esi+4],0
						mov byte ptr [esi+9],0
						add esi,6
						invoke htodw,esi ; seem rec
						push eax
						sub esi,5
						invoke htodw,esi ; seem num
						pop ebx
						.if eax>0 && eax<2ffh && ebx>0 && ebx<0ffh
							push eax
							push ebx
							;read file
							invoke CreateFile,addr buffery,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
							mov	hReadFile,eax
							invoke GetFileSize,hReadFile,addr nBytes
							inc	eax
							mov	nBytes,eax
							invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
							mov	hMemFile,eax
							invoke ReadFile,hReadFile,hMemFile,nBytes,addr nBytes,FALSE
							;DbgDump hMemFile,16
							invoke CloseHandle,hReadFile
							; upload seem
							pop ebx ; rec
							pop eax ; num
							push eax
							push ebx
				            push    offset seem_data
				            push    0
					        push    0
						    push    ebx ;seem_rec
				    		push    eax ;seem_num
				    		invoke Cmd_RDELEM
				    		pop ebx
				    		pop eax
				    		dec     seem_read_bytes
							push 	hMemFile
				            push    seem_read_bytes ;bytes=filesize
					        push    0
						    push    ebx ;seem_rec
				    		push    eax ;seem_num
				    		call Seem_Write
							
							invoke GlobalFree,hMemFile
						.else
							invoke MessageBox,hWin,StrAddr("Invalid seem filename! Must be: xxxx_yyyy.seem"),StrAddr("Warning!"),MB_OK	
						.endif	
					.endif
				.endif
			.endif	
		.endif	
	.else  ;p2k filesystem
		.if isDir==1

			lea esi,buffer
			.if word ptr [esi]!=".." ; no parentdir
				invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr Fulldir1	; prev path
				invoke lstrcat,addr Fulldir1,addr buffer							; add new dir
				invoke lstrcat,addr Fulldir1,addr szSlash							; add "/"
				invoke SendDlgItemMessage,hWin,1016,WM_SETTEXT,0,addr Fulldir1		; set new fulldir
				mov esi,offset Fulldir1
				mov al,[esi]
				.while al!="/"	;step to first "/" = cut leading "P2k:"
					inc esi
					mov al,[esi]
				.endw
				invoke lstrcpy,addr P2kDirectory1,esi	; set actual dir
				invoke P2kGetFileList1,hWin
				;invoke SendMessage,hList1,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc1
				;invoke UpdatelParam1
			.else
				;goto parentdir 	
				invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr Fulldir1
				mov esi,offset Fulldir1
				mov al,[esi]
				.while al!=0	; step to the end
					inc esi
					mov al,[esi]
				.endw
				dec esi			; step over the last "/"
				dec esi
				.while al!="/"	; step back to the next "/"
					dec esi

					mov al,[esi]
				.endw
				inc esi
				mov byte ptr [esi],0
				invoke SendDlgItemMessage,hWin,1016,WM_SETTEXT,0,addr Fulldir1
				mov esi,offset Fulldir1	; CUT "P2k:"
				mov al,[esi]
				.while al!="/"
					inc esi
					mov al,[esi]
				.endw
				invoke lstrcpy,addr P2kDirectory1,esi

					invoke P2kGetFileList1,hWin
					;invoke SendMessage,hList1,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc1
					;invoke UpdatelParam1
			.endif
		.else ; activate file
			; 1:download to temp folder buffer=filename
			; dest filename = Launchdir + "\Temp\" + buffer
			invoke lstrcpy,Addr buffery,addr LaunchDir
			invoke lstrcat,Addr buffery,addr Tempdir
			invoke SendMessage,hList1,LVM_GETNEXTITEM,-1,LVNI_SELECTED ;FOCUSED
			mov esi,eax
			invoke P2kCopy_down,esi,hWin,hList1,addr buffery
			invoke lstrcat,addr buffery,addr bufferx ;dest filename+path
			invoke ShellExecute,hWin,NULL,addr buffery,NULL,NULL,SW_SHOWDEFAULT
		.endif	
	.endif		
	invoke SendMessage,hList1,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc1
	invoke UpdatelParam1
	ret
ShowCurrentFocus1 endp
;
; Activating a listview entry (on dir = change directory) Right panel
;
ShowCurrentFocus2 proc uses esi ecx hWin:DWORD
	LOCAL lvi:LV_ITEM
	LOCAL buffer[256]:BYTE
	LOCAL buffer2[256]:BYTE
	LOCAL Row:DWORD
	LOCAL sfi:SHFILEINFO
	LOCAL Seemname:DWORD
	LOCAL Item:DWORD
	
	invoke SendMessage,hList2,LVM_GETNEXTITEM,-1,LVNI_FOCUSED
	mov lvi.iItem,eax
	push eax
	mov lvi.iSubItem,1 ;*0
	mov lvi.imask,LVIF_TEXT
	lea eax,buffer
	mov lvi.pszText,eax
	mov lvi.cchTextMax,256
	; get the item
	invoke SendMessage,hList2,LVM_GETITEM,0,addr lvi    ; buffer:filename
	lea eax,buffer
	.if byte ptr [eax]=="<"
		mov isDir,1 
	.else	
		mov isDir,0 
	.endif
	
	mov lvi.iSubItem,0
	pop lvi.iItem
	mov lvi.imask,LVIF_TEXT
	lea eax,buffer
	mov lvi.pszText,eax
	mov lvi.cchTextMax,256
	; get the item
	invoke SendMessage,hList2,LVM_GETITEM,0,addr lvi
	

	lea esi,buffer
	mov ax,[esi]
	.if ax==".."
		mov isUpDir,1
	.else
		mov isUpDir,0
	.endif
	.if Drive2>4  ; local filesystem
	;.if Drive2!=0  ; local filesystem
		invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr Fulldir2	; prev path
		invoke lstrcat,addr Fulldir2,addr szBackslash	; add "\"
		invoke lstrcat,addr Fulldir2,addr buffer		; add "new dir" (even if it is "..")
		invoke SetCurrentDirectory,addr Fulldir2 		; set new dir
		.if eax==0  ; error this is file, not dir
			;invoke logstat,addr buffer
			invoke ShellExecute,hWin,NULL,addr buffer,NULL,NULL,SW_SHOWDEFAULT
		.else
		invoke GetCurrentDirectory,255,addr Fulldir2	; get new dir
		invoke SendDlgItemMessage,hWin,1015,WM_SETTEXT,0,addr Fulldir2
		invoke FillFileInfo2,hWin	; update listview with files of new dir
		.endif
	.elseif Drive2==4  ;p2k seemroot
		.if isSeemRoot==1
			invoke lstrcat,addr Fulldir2,esi
			invoke SendDlgItemMessage,hWin,1015,WM_SETTEXT,0,addr Fulldir2
			; set seem name
			invoke lstrcpy,addr phone_model,esi
			invoke htodw,esi
			mov Seemname,eax
			mov isSeemRoot,0
			invoke SendMessage,hList2,LVM_DELETEALLITEMS,0,0
			mov Row,0
			; put ".."
		    mov lvi.imask, LVIF_TEXT or LVIF_IMAGE or LVIF_PARAM
			push Row
			pop lvi.iItem	
			mov lvi.iSubItem,0
			lea eax,offset szParentdir
			mov lvi.pszText,eax
			push Row
			pop lvi.lParam
	        INVOKE SHGetFileInfo,lvi.pszText, 0, addr sfi, sizeof SHFILEINFO,SHGFI_SYSICONINDEX or SHGFI_SMALLICON or SHGFI_TYPENAME or SHGFI_ATTRIBUTES
	        mov     eax,sfi.iIcon
		    mov     lvi.iImage, eax
			invoke SendMessage,hList2, LVM_INSERTITEM,0, addr lvi
			mov lvi.imask,LVIF_TEXT
			inc lvi.iSubItem
			invoke lstrcpy,addr buffer,addr szDirMark
			lea eax,buffer
			mov lvi.pszText,eax
			invoke SendMessage,hList2,LVM_SETITEM, 0,addr lvi
			; get list of records
			mov Item,0
			mov eax,0ffh
			inc eax
			shl eax,16
			invoke SendMessage,hBar,PBM_SETRANGE,0,eax
			invoke SendMessage,hBar,PBM_SETSTEP,1,0
			invoke SendMessage,hBar,PBM_SETPOS,0,0
			invoke LockWindowUpdate,hList2
			.while Item!=0ffh 
				inc Item
				inc Row
		        push    offset seem_data
	            push    1
	            push    0
		        push    Item
	            push    Seemname
	            mov stay_quiet,1
	            invoke Cmd_RDELEM
	            mov stay_quiet,0
	            .if eax==0
					mov esi,offset phone_model
					add esi,4
					mov byte ptr [esi],"_"
					inc esi
					invoke dw2ah,Item,esi
					mov eax,[esi+4]
					mov [esi],eax
					mov dword ptr [esi+4],'ees.'
					mov byte ptr [esi+4+4],'m'
					mov byte ptr [esi+4+5],0
					sub esi,5
					push esi
					; add item to hList2
					; get image for file
					invoke lstrcpy,addr buffery,addr LaunchDir
					invoke lstrcat,addr buffery,addr Templates
					invoke lstrcat,addr buffery,StrAddr("_.seem")
				    mov lvi.imask, LVIF_TEXT or LVIF_IMAGE or LVIF_PARAM
					push Row
					pop lvi.iItem	
					mov lvi.iSubItem,0
					pop lvi.pszText
					push Row
					pop lvi.lParam
			        INVOKE     SHGetFileInfo,addr buffery, 0, addr sfi, sizeof SHFILEINFO,SHGFI_SYSICONINDEX
			        .if eax==0
			        	mov eax,UnknownIcon
			        	mov sfi.iIcon,eax
			        .endif
			        mov     eax,sfi.iIcon
			        mov     lvi.iImage, eax
					invoke SendMessage,hList2, LVM_INSERTITEM,0, addr lvi
					; get size
			        push    offset seem_data
		            push    0
		            push    0
			        push    Item
		            push    Seemname
		            invoke Cmd_RDELEM
		            mov eax,seem_read_bytes
		            dec eax
		            lea esi,buffer
		            invoke dwtoa,eax,esi
		            mov lvi.pszText,esi
					inc lvi.iSubItem
					mov lvi.imask,LVIF_TEXT
					invoke SendMessage,hList2,LVM_SETITEM, 0,addr lvi
					dec lvi.iSubItem
				.else 
					mov	Item,0ffh	
					invoke SendMessage,hBar,PBM_SETPOS,0ffh,0
	            .endif
				invoke SendDlgItemMessage,hWin,1014,PBM_STEPIT,0,0
			.endw
			invoke LockWindowUpdate,NULL
		.else
			; check if ".." and go root
			.if isUpDir==1
				invoke P2kGetSeemList2,hWin
				mov isSeemRoot,1
			.else
				; download to /Temp
				; read seem
		        push    offset seem_data
	            push    0
	            push    0
				; get numbers
				;lea esi,buffer
				mov byte ptr [esi+4],0
				mov byte ptr [esi+9],0
				add esi,5
				invoke htodw,esi ; seem rec
				push eax
				sub esi,5
				invoke htodw,esi ; seem num
				push eax
		        ;push    Item
	            ;push    Seemname
	            invoke Cmd_RDELEM
				; save seem
				invoke lstrcpy,addr bufferx,addr LaunchDir
				invoke lstrcat,addr bufferx,StrAddr ("\Temp\")
				lea esi,buffer
				mov byte ptr [esi+4],"_"
				mov byte ptr [esi+9],"."
				invoke lstrcat,addr bufferx,esi
				invoke DeleteFile,addr bufferx ;savename
				invoke CreateFile,addr bufferx,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0
				mov hSaveFile,eax
				invoke SetFilePointer,hSaveFile,0,0,FILE_BEGIN
				mov eax,offset seem_data
				inc eax
				mov ecx,seem_read_bytes
				dec ecx
				invoke WriteFile,hSaveFile,eax,ecx,addr writtenb,0
				invoke CloseHandle,hSaveFile
				; run xvi32 to view seem
				invoke lstrcpy,addr bufferx,addr LaunchDir
				invoke lstrcat,addr bufferx,StrAddr ("\xvi32.exe")
				invoke lstrcpy,addr buffery,StrAddr ('"')
				invoke lstrcat,addr buffery,addr LaunchDir
				invoke lstrcat,addr buffery,StrAddr ("\Temp\")
				invoke lstrcat,addr buffery,esi
				invoke lstrcat,addr buffery,StrAddr ('"')
				
				invoke lstrcat,addr bufferx,StrAddr (" ")
				invoke lstrcat,addr bufferx,addr buffery
				
				lea edi,buffer2
				invoke lstrcpy,edi,addr LaunchDir
				invoke lstrcat,edi,StrAddr ("\Temp\")
				invoke FindFirstChangeNotification,edi,FALSE,FILE_NOTIFY_CHANGE_LAST_WRITE
				;invoke logstat,addr buffery
				push eax
    	        invoke ShowWindow,hWin,SW_MINIMIZE      
				invoke CreateProcess,NULL,addr bufferx,NULL,NULL,FALSE,\ 
    	              NORMAL_PRIORITY_CLASS,\ 
    	              NULL,NULL,ADDR startInfo,ADDR processInfo
				invoke WaitForSingleObject,processInfo.hProcess,INFINITE
    	        invoke ShowWindow,hWin,SW_RESTORE      
				; check if file changed
				pop eax
				invoke WaitForSingleObject,eax,200
				.if eax==0
					; if changed drop a messagebox "write?"
					; write seem
					invoke MessageBox,hWin,StrAddr("Seem data changed, do you want to write to the phone?"),StrAddr("Warning, data changed!"),MB_YESNO
					.if eax==IDYES
						; write seem file
						lea esi,buffer
						invoke lstrcpy,addr buffery,addr LaunchDir
						invoke lstrcat,addr buffery,StrAddr ("\Temp\")
						invoke lstrcat,addr buffery,esi
						;invoke logstat
						mov byte ptr [esi+4],0
						mov byte ptr [esi+9],0
						add esi,6
						invoke htodw,esi ; seem rec
						push eax
						sub esi,5
						invoke htodw,esi ; seem num
						pop ebx
						.if eax>0 && eax<2ffh && ebx>0 && ebx<0ffh
							push eax
							push ebx
							;read file
							invoke CreateFile,addr buffery,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
							mov	hReadFile,eax
							invoke GetFileSize,hReadFile,addr nBytes
							inc	eax
							mov	nBytes,eax
							invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
							mov	hMemFile,eax
							invoke ReadFile,hReadFile,hMemFile,nBytes,addr nBytes,FALSE
							;DbgDump hMemFile,16
							invoke CloseHandle,hReadFile
							; upload seem
							pop ebx ; rec
							pop eax ; num
							push eax
							push ebx
				            push    offset seem_data
				            push    0
					        push    0
						    push    ebx ;seem_rec
				    		push    eax ;seem_num
				    		invoke Cmd_RDELEM
				    		pop ebx
				    		pop eax
				    		dec     seem_read_bytes
							push 	hMemFile
				            push    seem_read_bytes ;bytes=filesize
					        push    0
						    push    ebx ;seem_rec
				    		push    eax ;seem_num
				    		call Seem_Write
							
							invoke GlobalFree,hMemFile
						.else
							invoke MessageBox,hWin,StrAddr("Invalid seem filename! Must be: xxxx_yyyy.seem"),StrAddr("Warning!"),MB_OK	
						.endif	
					.endif
				.endif
			.endif	
		.endif	
	.else  ;p2k filesystem
		.if isDir==1
			lea esi,buffer
			.if word ptr [esi]!=".." ; no parentdir
				invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr Fulldir2
				invoke lstrcat,addr Fulldir2,addr buffer   ;add new dirname
				invoke lstrcat,addr Fulldir2,addr szSlash  ;add slash
				invoke SendDlgItemMessage,hWin,1015,WM_SETTEXT,0,addr Fulldir2
				mov esi,offset Fulldir2    ;cut "P2k:"
				mov al,[esi]
				.while al!="/"
					inc esi
					mov al,[esi]
				.endw
				invoke lstrcpy,addr P2kDirectory2,esi
					invoke P2kGetFileList2,hWin
					;invoke SendMessage,hList2,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc2
					;invoke UpdatelParam2
			.else
				;goto parentdir 	
				invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr Fulldir2
				mov esi,offset Fulldir2
				mov al,[esi]
				.while al!=0	; step to the end
					inc esi
					mov al,[esi]
				.endw
				dec esi			; step over the last "/"
				dec esi
				.while al!="/"	; step back to the next "/"
					dec esi
					mov al,[esi]
				.endw
				inc esi
				mov byte ptr [esi],0
				invoke SendDlgItemMessage,hWin,1015,WM_SETTEXT,0,addr Fulldir2
				mov esi,offset Fulldir2
				mov al,[esi]
				.while al!="/"		; CUT "P2k:"
					inc esi
					mov al,[esi]
				.endw
				invoke lstrcpy,addr P2kDirectory2,esi
					invoke P2kGetFileList2,hWin
					;invoke SendMessage,hList2,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc2
					;invoke UpdatelParam2
			.endif
		.else ; activate file
			; 1:download to temp folder buffer=filename
			; dest filename = Launchdir + "\Temp\" + buffer
			invoke lstrcpy,Addr buffery,addr LaunchDir
			invoke lstrcat,Addr buffery,addr Tempdir
			invoke SendMessage,hList2,LVM_GETNEXTITEM,-1,LVNI_SELECTED ;FOCUSED
			mov esi,eax
			invoke P2kCopy_down,esi,hWin,hList2,addr buffery
			invoke lstrcat,addr buffery,addr bufferx ;dest filename+path
			invoke ShellExecute,hWin,NULL,addr buffery,NULL,NULL,SW_SHOWDEFAULT
		.endif		
	.endif		
	
	invoke SendMessage,hList2,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc2
	invoke UpdatelParam2
	ret
ShowCurrentFocus2 endp
;
; Maintain the Current dir display - Left panel
;
SetCurrDir1 proc uses esi hWin:DWORD, Drive11:DWORD
		invoke SendDlgItemMessage,hWin,1005,CB_GETLBTEXT,Drive11,addr szDrive1
		invoke logstat,addr szDrive1
		mov esi,offset szDrive1
		.if byte ptr [esi]!="_"
			mov byte ptr [esi+2],0
		.else 
			inc esi	
		.endif	
		invoke SetCurrentDirectory,esi ;addr szDrive1
		push eax
		invoke GetCurrentDirectory,255,addr bufferx
		invoke SendDlgItemMessage,hWin,1016,WM_SETTEXT,0,addr bufferx
		pop eax
		ret
SetCurrDir1 endp
;
; Maintain the Current dir display - Right panel
;
SetCurrDir2 proc uses esi hWin:DWORD, Drive22:DWORD
		invoke SendDlgItemMessage,hWin,1006,CB_GETLBTEXT,Drive22,addr szDrive2
		mov esi,offset szDrive2
			mov byte ptr [esi+2],0
		invoke SetCurrentDirectory,addr szDrive2
		push eax
		invoke GetCurrentDirectory,255,addr bufferx
		invoke SendDlgItemMessage,hWin,1015,WM_SETTEXT,0,addr bufferx
		pop eax
		ret
SetCurrDir2 endp
P2kGetSeemList1 proc uses edi esi ebx hWin:DWORD
	LOCAL lvi:LV_ITEM
	LOCAL buffer[256]:BYTE
	LOCAL sfi:SHFILEINFO
	LOCAL lvfi:LV_FINDINFO
	LOCAL row:DWORD
		invoke LockWindowUpdate,hList1
		invoke lstrcpy,addr Fulldir1,StrAddr ("P2k:/seems/")
		invoke SendDlgItemMessage,hWin,1016,WM_SETTEXT,0,addr Fulldir1 
		invoke SendMessage,hList1,LVM_DELETEALLITEMS,0,0
		mov eax,nSeemCount
		inc eax
		shl eax,16
		invoke SendMessage,hBar,PBM_SETRANGE,0,eax
		invoke SendMessage,hBar,PBM_SETSTEP,1,0
		invoke SendMessage,hBar,PBM_SETPOS,0,0
		mov edi,hMemSeemPtrs
		mov row,0
		mov eax,nSeemCount
		.while row!=eax
			mov esi,[edi]
		    mov lvi.imask, LVIF_TEXT or LVIF_IMAGE or LVIF_PARAM
			push row
			pop lvi.iItem	
			mov lvi.iSubItem,0
			mov eax,esi
			mov lvi.pszText,eax
			push row
			pop lvi.lParam
			; get image for file
			invoke lstrcpy,addr bufferx,StrAddr("D")
			mov esi,offset bufferx
			invoke lstrcpy,addr buffery,addr LaunchDir
			invoke lstrcat,addr buffery,addr Templates
			invoke lstrcat,addr buffery,esi
	        INVOKE     SHGetFileInfo,addr buffery, 0, addr sfi, sizeof SHFILEINFO,SHGFI_SYSICONINDEX
	        .if eax==0
	        	mov eax,UnknownIcon
	        	mov sfi.iIcon,eax
	        .endif
	        mov     eax,sfi.iIcon
	        mov     lvi.iImage, eax
			invoke SendMessage,hList1, LVM_INSERTITEM,0, addr lvi
				; filesize
				mov lvi.imask,LVIF_TEXT
				mov lvi.iSubItem,1
					invoke lstrcpy,addr buffer,StrAddr("< SEEM >")
				lea eax,buffer
				mov lvi.pszText,eax
;				pop eax
;				push eax
;				mov ax,[eax]
				invoke SendMessage,hList1,LVM_SETITEM, 0,addr lvi
				mov esi,[edi]
				invoke htodw,esi
				shl eax,2  ;*4
				mov ebx,hMemSeemFPtrs

				add ebx,eax
				mov lvi.iSubItem,2
					invoke lstrcpy,addr buffer,[ebx]
				lea eax,buffer
				mov lvi.pszText,eax
				invoke SendMessage,hList1,LVM_SETITEM, 0,addr lvi
				
			add edi,4
			inc row
			invoke SendDlgItemMessage,hWin,1014,PBM_STEPIT,0,0
			mov eax,nSeemCount
		.endw	
		invoke LockWindowUpdate,NULL
		ret
P2kGetSeemList1 endp
P2kGetSeemList2 proc uses edi esi ebx hWin:DWORD
	LOCAL lvi:LV_ITEM
	LOCAL buffer[256]:BYTE
	LOCAL sfi:SHFILEINFO
	LOCAL lvfi:LV_FINDINFO
	LOCAL row:DWORD
		invoke LockWindowUpdate,hList2
		invoke lstrcpy,addr Fulldir2,StrAddr ("P2k:/seems/")
		invoke SendDlgItemMessage,hWin,1015,WM_SETTEXT,0,addr Fulldir2 
		invoke SendMessage,hList2,LVM_DELETEALLITEMS,0,0
		mov eax,nSeemCount
		inc eax
		shl eax,16
		invoke SendMessage,hBar,PBM_SETRANGE,0,eax
		invoke SendMessage,hBar,PBM_SETSTEP,1,0
		invoke SendMessage,hBar,PBM_SETPOS,0,0
		mov edi,hMemSeemPtrs
		mov row,0
		mov eax,nSeemCount
		.while row!=eax
			mov esi,[edi]
		    mov lvi.imask, LVIF_TEXT or LVIF_IMAGE or LVIF_PARAM
			push row
			pop lvi.iItem	
			mov lvi.iSubItem,0
			mov eax,esi
			mov lvi.pszText,eax
			push row
			pop lvi.lParam
			; get image for file
			invoke lstrcpy,addr bufferx,StrAddr("D")
			mov esi,offset bufferx
			invoke lstrcpy,addr buffery,addr LaunchDir
			invoke lstrcat,addr buffery,addr Templates
			invoke lstrcat,addr buffery,esi
	        INVOKE     SHGetFileInfo,addr buffery, 0, addr sfi, sizeof SHFILEINFO,SHGFI_SYSICONINDEX
	        .if eax==0
	        	mov eax,UnknownIcon
	        	mov sfi.iIcon,eax
	        .endif
	        mov     eax,sfi.iIcon
	        mov     lvi.iImage, eax
			invoke SendMessage,hList2, LVM_INSERTITEM,0, addr lvi
				; filesize
				mov lvi.imask,LVIF_TEXT
				mov lvi.iSubItem,1
					invoke lstrcpy,addr buffer,StrAddr("< SEEM >")
				lea eax,buffer
				mov lvi.pszText,eax
;				pop eax
;				push eax
;				mov ax,[eax]
				invoke SendMessage,hList2,LVM_SETITEM, 0,addr lvi
				mov esi,[edi]
				invoke htodw,esi
				shl eax,2  ;*4
				mov ebx,hMemSeemFPtrs
				add ebx,eax
				mov lvi.iSubItem,2
					invoke lstrcpy,addr buffer,[ebx]
				lea eax,buffer
				mov lvi.pszText,eax
				invoke SendMessage,hList2,LVM_SETITEM, 0,addr lvi
				
			add edi,4
			inc row
			invoke SendDlgItemMessage,hWin,1014,PBM_STEPIT,0,0
			mov eax,nSeemCount
		.endw	
		invoke LockWindowUpdate,NULL
		ret
P2kGetSeemList2 endp
;
; Left: insert 1 row to listview lpFind = P2k file record in memory
; P2k filesystem
;
ShowP2kFileInfo1 proc uses esi edi row:DWORD, lpFind:DWORD
	LOCAL lvi:LV_ITEM
	LOCAL buffer[256]:BYTE
	LOCAL sfi:SHFILEINFO
	LOCAL lvfi:LV_FINDINFO
	LOCAL isFolder:DWORD
	LOCAL isRootMatch:DWORD
	; esi=addr of string
	; check if files in actual dir	
	mov edi,offset P2kDirectory1
	mov esi,lpFind
	mov isRootMatch,0
	;
	; V8 mod, files staring with double slash  '//'
	;
	
	;
	; V3re mod, files without '/a/'
	;
	; check if root
	.if byte ptr [edi+1]==0
		; check if filename has no '/' at first byte
		.if byte ptr [esi]!='/'
			mov isRootMatch,1
		.endif	
	.endif
	invoke GetP2kSize
	;mov eax,[esi+108h]   ; get filesize ;ppppp
    xchg    ah, al
    rol     eax,10h
    xchg    ah,al
	mov [P2kFilesize],eax
	invoke GetAttrib
	;mov eax,[esi+104h]   ; get attrib  ;ppppp
	mov [P2kFileattrib],eax
	and eax,1000h
	mov isFolder,eax
	mov al,[esi]
	.while al==[edi] ; dirname match? filtered file display
		inc esi
		inc edi
		mov al,[esi]
	.endw
	.if byte ptr [edi]==0 || isRootMatch==1  ; match
		; get filename or dirname to a buffer
		mov edi,offset bufferx 
		mov al,[esi]
		nop
		.while al!="/" ;|| al!=0
			.BREAK .if al==0
			mov [edi],al
			inc esi
			inc edi
			mov al,[esi]
			nop
		.endw
		; if al==0 then file, else directory
		.if al==0 && isFolder!=1000h
			mov isDir,0
		.else	
			mov isDir,1
		.endif
		mov byte ptr [edi],0
		mov esi,offset bufferx
	    mov lvi.imask, LVIF_TEXT or LVIF_IMAGE or LVIF_PARAM
		push row
		pop lvi.iItem	
		mov lvi.iSubItem,0
		mov eax,esi
		push eax
		mov lvi.pszText,eax
		push row

		pop lvi.lParam
	        ; if already exist do not insert
	        mov lvfi.flags,LVFI_STRING	
			push lvi.pszText
	        pop lvfi.psz
	        invoke SendMessage,hList1,LVM_FINDITEM,-1,addr lvfi
	        .if eax==-1 ; not found
				; get image for file
				invoke lstrcpy,addr bufferx,eax
				mov esi,offset bufferx
				invoke lstrlen,addr bufferx
				add eax,esi
				mov esi,eax
				.while byte ptr [esi]!="."
					dec esi
				.endw
				dec esi
				mov al,"_"
		        .if isDir==1
		        	mov al,"D"	
		        .endif
		        mov ah,[esi]
				push eax
				mov [esi],al
				push esi
				invoke lstrcpy,addr buffery,addr LaunchDir
				invoke lstrcat,addr buffery,addr Templates
				pop esi
				push esi
				invoke lstrcat,addr buffery,esi
				pop esi
				pop eax
				mov [esi],ah
		        INVOKE     SHGetFileInfo,addr buffery, 0, addr sfi, sizeof SHFILEINFO,SHGFI_SYSICONINDEX
		        .if eax==0
		        	mov eax,UnknownIcon
		        	mov sfi.iIcon,eax
		        .endif
		        mov     eax,sfi.iIcon
		        mov     lvi.iImage, eax
	        
				invoke SendMessage,hList1, LVM_INSERTITEM,0, addr lvi
				; filesize
				mov lvi.imask,LVIF_TEXT
				mov lvi.iSubItem,1
				invoke wsprintf,addr buffer, addr template,P2kFilesize
				.if isDir==1
					invoke lstrcpy,addr buffer,addr szDirMark
				.endif
				lea eax,buffer
				mov lvi.pszText,eax
				pop eax
				push eax
				mov ax,[eax]
				invoke SendMessage,hList1,LVM_SETITEM, 0,addr lvi
				; fileattrib
				mov lvi.imask,LVIF_TEXT
				mov lvi.iSubItem,2
				invoke dw2hex,P2kFileattrib,addr buffer
				;invoke logstat,addr buffer
				;spacing
				lea esi,buffer	  ; 'OW    ATTR'
				.if isUSBLAN==3
					mov ax,[esi+2]   ; owner
					mov [esi],ax
					mov eax,[esi+4]   ; attrib
					mov [esi+6],eax
				.else
					mov eax,[esi+2]   ; attrib
					mov [esi+6],eax
				.endif
				mov dword ptr [esi+2],"    "
				mov byte ptr [esi+10],0 ; end
				lea eax,buffer
				mov lvi.pszText,eax
				pop eax
				mov ax,[eax]
				invoke SendMessage,hList1,LVM_SETITEM, 0,addr lvi
				inc row
			.else 
				pop eax
			.endif
	.else
	.endif
	mov eax,row	
	ret
ShowP2kFileInfo1 endp
;
; Right: insert 1 row to listview lpFind = P2k file record in memory
; P2k filesystem
;
ShowP2kFileInfo2 proc uses esi edi row:DWORD, lpFind:DWORD
	LOCAL lvi:LV_ITEM
	LOCAL buffer[256]:BYTE
	LOCAL sfi:SHFILEINFO
	LOCAL lvfi:LV_FINDINFO
	LOCAL isFolder:DWORD
	LOCAL isRootMatch:DWORD
	; esi=addr of string
	; check if files in actual dir	
	mov edi,offset P2kDirectory2
	mov esi,lpFind
	mov isRootMatch,0
	;
	; V3re mod, files without '/a/'
	;
	; check if root
	.if byte ptr [edi+1]==0
		; check if filename has no '/' at first byte
		.if byte ptr [esi]!='/'
			mov isRootMatch,1
		.endif	
	.endif
	invoke GetP2kSize
	;mov eax,[esi+108h]  ;ppppp
    xchg    ah, al
    rol     eax,10h
    xchg    ah,al
	mov [P2kFilesize],eax
	invoke GetAttrib
	;mov eax,[esi+104h]   ; get attrib ;ppppp
	mov [P2kFileattrib],eax
	and eax,1000h
	mov isFolder,eax
	mov al,[esi]
	.while al==[edi]
		inc esi
		inc edi
		mov al,[esi]
	.endw
	.if byte ptr [edi]==0 || isRootMatch==1  ; match
		; get filename or dirname to buffery
		mov edi,offset bufferx 
		mov al,[esi]
		nop
		.while al!="/" ;|| al!=0
			.BREAK .if al==0
			mov [edi],al
			inc esi
			inc edi
			mov al,[esi]
			nop
		.endw
		; if al==0 then file, else directory
		.if al==0 && isFolder!=1000h
			mov isDir,0
		.else	
			mov isDir,1
		.endif
		mov byte ptr [edi],0
		mov esi,offset bufferx
	    mov lvi.imask, LVIF_TEXT or LVIF_IMAGE or LVIF_PARAM
		push row
		pop lvi.iItem	
		mov lvi.iSubItem,0
		mov eax,esi
		push eax
		mov lvi.pszText,eax

		push row
		pop lvi.lParam
	        ; if already exist don ot insert
	        mov lvfi.flags,LVFI_STRING	
			push lvi.pszText
	        pop lvfi.psz
	        invoke SendMessage,hList2,LVM_FINDITEM,-1,addr lvfi
	        .if eax==-1
	        
				; get image for file
				invoke lstrcpy,addr bufferx,eax
				mov esi,offset bufferx
				invoke lstrlen,addr bufferx
				add eax,esi
				mov esi,eax
				.while byte ptr [esi]!="."
					dec esi
				.endw
				dec esi
				mov al,"_"
		        .if isDir==1
		        	mov al,"D"	
		        .endif
		        mov ah,[esi]
		        push eax
				mov [esi],al
				push esi
				invoke lstrcpy,addr buffery,addr LaunchDir
				invoke lstrcat,addr buffery,addr Templates
				pop esi
				push esi
				invoke lstrcat,addr buffery,esi
				pop esi
				pop eax
				mov [esi],ah
		        INVOKE     SHGetFileInfo,addr buffery, 0, addr sfi, sizeof SHFILEINFO,SHGFI_SYSICONINDEX
		        .if eax==0
		        	mov eax,UnknownIcon
		        	mov sfi.iIcon,eax
		        .endif
		        mov     eax,sfi.iIcon
		        mov     lvi.iImage, eax
	        
				invoke SendMessage,hList2, LVM_INSERTITEM,0, addr lvi
				; filesize
				mov lvi.imask,LVIF_TEXT
				inc lvi.iSubItem
				invoke wsprintf,addr buffer, addr template,P2kFilesize ;[edi].nFileSizeLow
				.if isDir==1
					invoke lstrcpy,addr buffer,addr szDirMark
				.endif
				lea eax,buffer
				mov lvi.pszText,eax
				pop eax
				push eax
				mov ax,[eax]
				invoke SendMessage,hList2,LVM_SETITEM, 0,addr lvi
				; fileattrib
				mov lvi.imask,LVIF_TEXT
				mov lvi.iSubItem,2
				invoke dw2hex,P2kFileattrib,addr buffer
				;spacing
				lea esi,buffer
				mov eax,[esi+2]
				mov [esi+6],eax
				mov dword ptr [esi+2],"    "
				mov byte ptr [esi+10],0
				lea eax,buffer
				mov lvi.pszText,eax
				pop eax
				mov ax,[eax]
				invoke SendMessage,hList2,LVM_SETITEM, 0,addr lvi


				inc row
			.else
				pop eax	
			.endif
	.endif	
	mov eax,row
	ret
ShowP2kFileInfo2 endp
P2kGetFileList1 proc uses esi ecx hWin:DWORD
LOCAL Row:DWORD
LOCAL lvi:LV_ITEM
LOCAL lvc:LV_COLUMN 
LOCAL sfi:SHFILEINFO
LOCAL buffer[256]:BYTE

			.if _DevIF!=0
				.if P2kReady==0 ;&& isP2k05==0
					;invoke P2kGetFileList1HW
					invoke CreateThread,0,0,addr P2kGetFileListHW,0,0,0
					;invoke MessageBox,hWin,addr szWait,addr szWarning,MB_OK + MB_ICONASTERISK
					invoke DialogBoxParam,hInstance, 1700,hWin,OFFSET WaitProc,NULL
				.else
				.endif
;----------------------------------------				
				mov eax,[SearchBuf_Ptr]
				mov [SearchBuf_Pos2],eax
				mov Row,0
				invoke SendMessage,hList1,LVM_DELETEALLITEMS,0,0
				mov esi,offset P2kDirectory1
				.if	word ptr [esi]!="/"	; insert parentdir ".."
				    mov lvi.imask, LVIF_TEXT or LVIF_IMAGE or LVIF_PARAM
					push Row
					pop lvi.iItem	
					mov lvi.iSubItem,0
					lea eax,offset szParentdir
					mov lvi.pszText,eax
					push Row
					pop lvi.lParam
			        INVOKE SHGetFileInfo,lvi.pszText, 0, addr sfi, sizeof SHFILEINFO,SHGFI_SYSICONINDEX or SHGFI_SMALLICON or SHGFI_TYPENAME or SHGFI_ATTRIBUTES
			        mov     eax,sfi.iIcon
	    		    mov     lvi.iImage, eax
					invoke SendMessage,hList1, LVM_INSERTITEM,0, addr lvi
					mov lvi.imask,LVIF_TEXT
					inc lvi.iSubItem
					invoke lstrcpy,addr buffer,addr szDirMark
					lea eax,buffer
					mov lvi.pszText,eax
					invoke SendMessage,hList1,LVM_SETITEM, 0,addr lvi
					inc Row
				.endif
				;
				mov esi,SearchBuf_Pos2

				mov eax,Row2 ;Files_found
				mov Row3,0
				.while Row3<eax ;695 ;testfilenum   ;eax  ;test Row!=12
					; elsõ 4 byte=hány record?
					mov eax,[esi]	
					xchg al,ah				; e398=3
					add esi,4
					mov ecx,eax
					.while ecx!=0
						push ecx
						push esi

						invoke ShowP2kFileInfo1,Row,esi
						pop esi
						mov Row,eax
						inc Row3
						add esi,P2kRecordSize ;10ch ;ppppp
						pop ecx
						dec ecx
					.endw
					mov eax,Row2 ;Files_found
	         	.endw
				mov P2kReady,1
			.else
				mov Drive1,6; c:
				; set 3. column label
				invoke SendMessage,hList1,LVM_GETCOLUMN,2,addr _lvc
				mov _lvc.imask,LVCF_TEXT				
				invoke GetMsgAddr,46
				mov _lvc.pszText,eax ;offset Heading4
				invoke SendMessage,hList1,LVM_SETCOLUMN,2,addr _lvc
				invoke SendMessage,hLB1,CB_SETCURSEL,Drive1,0	
				invoke SetCurrDir1,hWin,Drive1 
				invoke FillFileInfo1,hWin
				;invoke SendMessage,hList1,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc1
				;invoke UpdatelParam1
			.endif
			ret
P2kGetFileList1 endp					
P2kGetFileList2 proc uses esi ecx hWin:DWORD
LOCAL Row:DWORD
LOCAL lvi:LV_ITEM
LOCAL lvc:LV_COLUMN 
LOCAL sfi:SHFILEINFO
LOCAL buffer[256]:BYTE

			.if _DevIF!=0
				.if P2kReady==0 ;&& isP2k05==0
					;invoke P2kGetFileList1HW
					invoke CreateThread,0,0,addr P2kGetFileListHW,0,0,0
					;invoke MessageBox,hWin,addr szWait,addr szWarning,MB_OK + MB_ICONASTERISK
					invoke DialogBoxParam,hInstance, 1700,hWin,OFFSET WaitProc,NULL
				.else
				.endif
					mov eax,[SearchBuf_Ptr]
					;mov [SearchBuf_Pos],eax
					mov [SearchBuf_Pos2],eax
					mov Row,0
					invoke SendMessage,hList2,LVM_DELETEALLITEMS,0,0
					mov esi,offset P2kDirectory2
					.if	word ptr [esi]!="/"	; insert parentdir ".."
					    mov lvi.imask, LVIF_TEXT or LVIF_IMAGE or LVIF_PARAM
						push Row
						pop lvi.iItem	
						mov lvi.iSubItem,0
						lea eax,offset szParentdir
						mov lvi.pszText,eax
						push Row
						pop lvi.lParam
				        INVOKE SHGetFileInfo,lvi.pszText, 0, addr sfi, sizeof SHFILEINFO,SHGFI_SYSICONINDEX or SHGFI_SMALLICON or SHGFI_TYPENAME or SHGFI_ATTRIBUTES
				        mov     eax,sfi.iIcon
		    		    mov     lvi.iImage, eax
						invoke SendMessage,hList2, LVM_INSERTITEM,0, addr lvi
						mov lvi.imask,LVIF_TEXT
						inc lvi.iSubItem
						invoke lstrcpy,addr buffer,addr szDirMark
						lea eax,buffer
						mov lvi.pszText,eax
						invoke SendMessage,hList2,LVM_SETITEM, 0,addr lvi
						inc Row
					.endif	
					;
					;mov esi,SearchBuf_Pos
					mov esi,SearchBuf_Pos2
					mov eax,Row2 ;Files_found
	                ;mov Row2,0
	                mov Row3,0
					;.while Row2<eax ;testfilenum   ;eax  ;test Row!=12
					.while Row3<eax ;testfilenum   ;eax  ;test Row!=12
						; elsõ 4 byte=hány record?
						mov eax,[esi]	
						xchg al,ah				; e398=3
						add esi,4
						mov ecx,eax
						.while ecx!=0
							push ecx
							push esi
							invoke ShowP2kFileInfo2,Row,esi
							pop esi
							mov Row,eax
							;inc Row2
							inc Row3
							add esi,P2kRecordSize ;10ch	;ppppp
							pop ecx
							dec ecx
						.endw
						mov eax,Row2 ;Files_found
		         	.endw
					mov P2kReady,1
			.else
				.if isBatch==0
					mov Drive2,6  ; c:
					; set 3. column label
					invoke SendMessage,hList2,LVM_GETCOLUMN,2,addr lvc
					mov lvc.imask,LVCF_TEXT				
					invoke GetMsgAddr,46
					mov lvc.pszText,eax ;offset Heading4
					invoke SendMessage,hList2,LVM_SETCOLUMN,2,addr lvc
					invoke SendMessage,hLB2,CB_SETCURSEL,Drive2,0	
					invoke SetCurrDir2,hWin,Drive2 
					invoke FillFileInfo2,hWin
					;invoke SendMessage,hList2,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc2
					;invoke UpdatelParam2
				.endif	
			.endif			
			ret
P2kGetFileList2 endp
SelectFirst1 proc pos:DWORD
LOCAL lvi:LV_ITEM
		invoke SetFocus,hList1
		mov lvi.imask,LVIF_STATE
		mov lvi.iItem,-1
		mov lvi.state,0
		mov lvi.stateMask,LVIS_SELECTED+LVIS_FOCUSED
		invoke SendMessage,hList1,LVM_SETITEMSTATE,-1,addr lvi
		push pos
		pop lvi.iItem
		mov lvi.state,LVIS_SELECTED+LVIS_FOCUSED
		mov lvi.stateMask,LVIS_SELECTED+LVIS_FOCUSED
		invoke SendMessage,hList1,LVM_SETITEMSTATE,pos,addr lvi
		ret
SelectFirst1 endp					
SelectFirst2 proc pos:DWORD
LOCAL lvi:LV_ITEM
;		invoke SetFocus,hList2
;		mov lvi.imask,LVIF_STATE
;		mov lvi.iItem,0
;		mov lvi.state,LVIS_SELECTED+LVIS_FOCUSED
;		mov lvi.stateMask,LVIS_SELECTED+LVIS_FOCUSED
;		invoke SendMessage,hList2,LVM_SETITEMSTATE,pos,addr lvi
;		ret
		invoke SetFocus,hList2
		mov lvi.imask,LVIF_STATE
		mov lvi.iItem,-1
		mov lvi.state,0
		mov lvi.stateMask,LVIS_SELECTED+LVIS_FOCUSED
		invoke SendMessage,hList2,LVM_SETITEMSTATE,-1,addr lvi
		push pos
		pop lvi.iItem
		mov lvi.state,LVIS_SELECTED+LVIS_FOCUSED
		mov lvi.stateMask,LVIS_SELECTED+LVIS_FOCUSED
		invoke SendMessage,hList2,LVM_SETITEMSTATE,pos,addr lvi
		ret
SelectFirst2 endp					
EnumChild proc uses edi hwndChild:DWORD,lParam:DWORD
	LOCAL buffer[256]:BYTE
	PUBLIC hMemPtrs

;/* From Iczelions tutorial #27: "Subclassing" a tooltip */

	mov edi,lParam
	assume edi:ptr TOOLINFO
	push hwndChild
	pop [edi].uId
	or [edi].uFlags,TTF_IDISHWND
	;invoke GetWindowText,hwndChild,addr buffer,255
	;;;;invoke GetDlgItem,hWnd,1004
	;;;;mov hSzoba2,eax
	invoke GetWindowLong,hwndChild,GWL_ID
	.if eax==1012
		invoke GetMsgAddr,58
		;lea eax,TTbufferReread1
	.elseif eax==1013
		invoke GetMsgAddr,59
		;lea eax,TTbufferReread2


	.elseif	eax==1007
		invoke GetMsgAddr,60
		;lea eax,TTbufferView
	.elseif	eax==1026
		invoke GetMsgAddr,61
		;lea eax,TTbufferEdit
	.elseif eax==1008
		invoke GetMsgAddr,62
		;lea eax,TTbufferAttrib
	.elseif	eax==1027
		invoke GetMsgAddr,63
		;lea eax,TTbufferCopy
	.elseif	eax==1004
		invoke GetMsgAddr,64
		;lea eax,TTbufferMove
	.elseif	eax==1009
		invoke GetMsgAddr,65
		;lea eax,TTbufferNew
	.elseif	eax==1011
		invoke GetMsgAddr,66
		;lea eax,TTbufferDel
	.elseif	eax==1010
		invoke GetMsgAddr,67
		;lea eax,TTbufferRest
	.elseif	eax==1005
		invoke GetMsgAddr,68
		;lea eax,TTbufferSel1
	.elseif	eax==1006
		invoke GetMsgAddr,69
		;lea eax,TTbufferSel2
	.elseif	eax==1001
		invoke GetMsgAddr,70
		;lea eax,TTbufferLog
	.elseif	eax==1016
		invoke GetMsgAddr,71
		;lea eax,TTbufferPath
	.elseif	eax==1015
		invoke GetMsgAddr,71
		;lea eax,TTbufferPath
	.elseif	eax==1014
		invoke GetMsgAddr,72
		;lea eax,TTbufferProg

	.elseif	eax==1511
		invoke GetMsgAddr,106
	.elseif	eax==1512
		invoke GetMsgAddr,107
	.elseif	eax==1513
		invoke GetMsgAddr,108
	.elseif	eax==1514
		invoke GetMsgAddr,109
	.elseif	eax==1566
		invoke GetMsgAddr,110
	.elseif	eax==1562
		invoke GetMsgAddr,111
	.elseif	eax==1561
		invoke GetMsgAddr,112
	.elseif	eax==1560
		invoke GetMsgAddr,113
	.elseif	eax==1565
		invoke GetMsgAddr,114
	.elseif	eax==1029
		invoke GetMsgAddr,116
	.elseif	eax==1853
		invoke GetMsgAddr,132
	.elseif	eax==1864
		invoke GetMsgAddr,133
	.elseif	eax==1865
		invoke GetMsgAddr,134
	.endif
	mov [edi].lpszText,eax
	;invoke SendMessage,hwndTool,TTM_SETDELAYTIME,TTDT_AUTOMATIC,2000
	invoke SendMessage,hwndTool,TTM_ADDTOOL,NULL,edi
	assume edi:nothing
	ret
EnumChild endp
_Hyperlink Proc uses ecx hlc_hWin:DWORD,hlc_uMsg:DWORD,hlc_wParam:DWORD,hlc_lParam:DWORD
	LOCAL hlc_tme				:TRACKMOUSEEVENT
	LOCAL hlc_ps				:PAINTSTRUCT
	LOCAL hlc_hdc				:DWORD
	LOCAL hlc_strlen			:DWORD
	LOCAL hlc_prc				:RECT
	LOCAL hlc_color				:DWORD
	LOCAL hlc_pt				:POINT
	LOCAL hlc_text[2048]		:BYTE
	LOCAL hlc_pSubject			:DWORD

	.IF hlc_uMsg == WM_SETTEXT
		; Get the border size
		invoke GetWindowRect,hlc_hWin,ADDR hlc_prc
		mov eax,hlc_prc.right
		sub eax,hlc_prc.left
		push eax
		mov eax,hlc_prc.bottom
		sub eax,hlc_prc.top
		push eax
		invoke GetClientRect,hlc_hWin,ADDR hlc_prc
		pop eax
		sub eax,hlc_prc.bottom
		pop ecx
		push eax
		sub ecx,hlc_prc.right
		push ecx

		invoke GetDC,hlc_hWin
		mov hlc_hdc,eax

		invoke GetWindowLong,hlc_hWin,20
		.IF !eax
			invoke GetStockObject,SYSTEM_FONT
		.endif
		invoke SelectObject,hlc_hdc,eax
		invoke lstrlen,hlc_lParam
		mov hlc_strlen,eax
		invoke DrawText,hlc_hdc,hlc_lParam,hlc_strlen,ADDR hlc_prc,DT_CALCRECT
		pop ecx
		add ecx,hlc_prc.right
		sub ecx,hlc_prc.left

		pop eax
		add eax,hlc_prc.bottom
		sub eax,hlc_prc.top
		invoke SetWindowPos,hlc_hWin,HWND_TOP,0,0,ecx,eax,SWP_NOMOVE or SWP_NOZORDER
		invoke ReleaseDC,hlc_hWin,hlc_hdc

	.ELSEIF hlc_uMsg == WM_CREATE
		invoke GlobalAlloc,GMEM_FIXED,4192
		invoke SetWindowLong,hlc_hWin,12,eax

	.ELSEIF hlc_uMsg == HLM_SETTYPE
		invoke SetWindowLong,hlc_hWin,0,hlc_lParam
		ret

	.ELSEIF hlc_uMsg == HLM_SETUNDERLINE
		invoke SetWindowLong,hlc_hWin,32,hlc_lParam
		ret

	.ELSEIF hlc_uMsg == HLM_SETHOTCOLOR
		invoke SetWindowLong,hlc_hWin,4,hlc_lParam

		; set the current color if necessary
		invoke GetCursorPos,ADDR hlc_pt
		invoke GetParent,hlc_hWin
		push eax
		mov ecx,eax
		invoke ScreenToClient,ecx,ADDR hlc_pt
		pop ecx
		invoke ChildWindowFromPoint,ecx,hlc_pt.x,hlc_pt.y
		.IF eax == hlc_hWin
			invoke SetWindowLong,hlc_hWin,16,hlc_lParam
			mov hlc_tme.cbSize,SIZEOF TRACKMOUSEEVENT
			mov hlc_tme.dwFlags,TME_LEAVE
			mov eax,hlc_hWin
			mov hlc_tme.hwndTrack,eax
			mov hlc_tme.dwHoverTime,HOVER_DEFAULT
			invoke _TrackMouseEvent,ADDR hlc_tme
		.endif
		invoke InvalidateRect,hlc_hWin,NULL,TRUE
		invoke UpdateWindow,hlc_hWin
		ret

	.ELSEIF hlc_uMsg == HLM_SETTEXTCOLOR
		invoke SetWindowLong,hlc_hWin,8,hlc_lParam

		; set the current color if necessary
		invoke GetCursorPos,ADDR hlc_pt
		invoke GetParent,hlc_hWin
		push eax
		mov ecx,eax
		invoke ScreenToClient,ecx,ADDR hlc_pt
		pop ecx
		invoke ChildWindowFromPoint,ecx,hlc_pt.x,hlc_pt.y
		.IF eax != hlc_hWin
			invoke SetWindowLong,hlc_hWin,16,hlc_lParam
		.endif
		invoke InvalidateRect,hlc_hWin,NULL,TRUE
		invoke UpdateWindow,hlc_hWin
		ret

	.ELSEIF hlc_uMsg == HLM_SETSUBJECT
		invoke lstrlen,hlc_lParam
		inc eax
		mov hlc_strlen,eax
		invoke GetWindowLong,hlc_hWin,24
		mov hlc_pSubject,eax
		.IF eax
			invoke GlobalFree,eax
		.endif
		invoke GlobalAlloc,GMEM_FIXED,hlc_strlen
		mov hlc_pSubject,eax
		.IF hlc_strlen >= 1024
			mov eax,hlc_lParam
			add eax,1023
			mov BYTE PTR [eax],0
		.endif
		invoke lstrcpy,hlc_pSubject,hlc_lParam
		invoke SetWindowLong,hlc_hWin,24,hlc_pSubject
		ret

	.ELSEIF hlc_uMsg == HLM_SETBODY
		invoke lstrlen,hlc_lParam
		inc eax
		mov hlc_strlen,eax
		invoke GetWindowLong,hlc_hWin,28
		mov hlc_pSubject,eax
		.IF eax
			invoke GlobalFree,eax
		.endif
		invoke GlobalAlloc,GMEM_FIXED,hlc_strlen
		mov hlc_pSubject,eax
		.IF hlc_strlen >= 1024
			mov eax,hlc_lParam
			add eax,1023
			mov BYTE PTR [eax],0
		.endif
		invoke lstrcpy,hlc_pSubject,hlc_lParam
		invoke SetWindowLong,hlc_hWin,28,hlc_pSubject
		ret

	.ELSEIF hlc_uMsg == WM_SETFONT
		; The def window proc does not do fonts so it has to be done manually
		invoke SetWindowLong,hlc_hWin,20,hlc_wParam
		invoke GetWindowText,hlc_hWin,ADDR hlc_text,256
		invoke SetWindowText,hlc_hWin,ADDR hlc_text
		.IF hlc_lParam
			invoke InvalidateRect,hlc_hWin,NULL,TRUE
			invoke UpdateWindow,hlc_hWin
		.ENDIF
		ret

	.ELSEIF hlc_uMsg == WM_LBUTTONDOWN
		invoke GetWindowLong,hlc_hWin,12
		mov hlc_pSubject,eax

		invoke GetWindowLong,hlc_hWin,0
		.IF eax == HLINK_URL
			lea eax,hlc_text
			invoke GetWindowText,hlc_hWin,hlc_pSubject,256

		.ELSEIF eax == HLINK_EMAIL
			jmp @F
				hlc_szMailTo 	db		"mailto:",0
				hlc_szSubject	db		"?subject=",0
				hlc_szBody		db		"&body=",0
				hlc_szOpen		db		"open",0
			@@:
			invoke lstrcpy,hlc_pSubject,OFFSET hlc_szMailTo
			mov eax,hlc_pSubject
			add eax,7
			invoke GetWindowText,hlc_hWin,eax,240
			invoke GetWindowLong,hlc_hWin,24
			.IF eax
				push eax
				invoke lstrcat,hlc_pSubject,OFFSET hlc_szSubject
				pop eax
				invoke lstrcat,hlc_pSubject,eax
				invoke GetWindowLong,hlc_hWin,28
				.IF eax
					push eax
					invoke lstrcat,hlc_pSubject,OFFSET hlc_szBody
					pop eax
					invoke lstrcat,hlc_pSubject,eax
				.ENDIF
			.endif

		.ENDIF
		invoke ShellExecute, hlc_hWin, OFFSET hlc_szOpen,hlc_pSubject, 0, 0, SW_SHOWNORMAL

	.ELSEIF hlc_uMsg == WM_MOUSEMOVE
		; The first mouse move message changes the color
		invoke GetWindowLong,hlc_hWin,4
		push eax
		invoke SetWindowLong,hlc_hWin,16,eax
		pop ecx
		.IF eax!=ecx
			invoke GetDlgCtrlID,hlc_hWin
			push eax
			invoke GetParent,hlc_hWin
			pop ecx
			invoke SendMessage,eax,HLM_ISHOT,ecx,hlc_hWin
			mov hlc_tme.cbSize,SIZEOF TRACKMOUSEEVENT
			mov hlc_tme.dwFlags,TME_LEAVE
			mov eax,hlc_hWin
			mov hlc_tme.hwndTrack,eax
			mov hlc_tme.dwHoverTime,HOVER_DEFAULT
			invoke _TrackMouseEvent,ADDR hlc_tme
			invoke InvalidateRect,hlc_hWin,NULL,TRUE
		.ENDIF

	.ELSEIF hlc_uMsg == WM_MOUSELEAVE
		invoke GetWindowLong,hlc_hWin,8
		invoke SetWindowLong,hlc_hWin,16,eax
		invoke InvalidateRect,hlc_hWin,NULL,TRUE
		ret

	.ELSEIF hlc_uMsg == WM_PAINT
		invoke GetWindowText,hlc_hWin,ADDR hlc_text,256
		mov hlc_strlen,eax
		invoke GetWindowLong,hlc_hWin,16
		mov hlc_color,eax
		invoke BeginPaint,hlc_hWin,ADDR hlc_ps
			mov hlc_hdc,eax
			invoke GetWindowLong,hlc_hWin,20
			invoke SelectObject,hlc_hdc,eax
			invoke SetTextColor,hlc_hdc,hlc_color
			invoke SetBkMode,hlc_hdc,TRANSPARENT
			invoke TextOut,hlc_hdc,0,0,ADDR hlc_text,hlc_strlen
			invoke GetWindowLong,hlc_hWin,32 ; Underline
			.IF eax
				; a line is drawn
				invoke CreatePen,PS_SOLID,1,hlc_color
				invoke SelectObject,hlc_hdc,eax
				push eax
				invoke GetClientRect,hlc_hWin,ADDR hlc_prc
				dec hlc_prc.bottom
				invoke MoveToEx,hlc_hdc,0,hlc_prc.bottom,NULL
				invoke LineTo,hlc_hdc,hlc_prc.right,hlc_prc.bottom
				pop eax
				invoke SelectObject,hlc_hdc,eax
				invoke DeleteObject,eax
			.endif
		invoke EndPaint,hlc_hWin,ADDR hlc_ps
		ret

	.ELSEIF hlc_uMsg == WM_DESTROY
		invoke GetWindowLong,hlc_hWin,12
		.IF eax
			invoke GlobalFree,eax
		.endif
		invoke GetWindowLong,hlc_hWin,24
		.IF eax
			invoke GlobalFree,eax
		.endif
		invoke GetWindowLong,hlc_hWin,28
		.IF eax
			invoke GlobalFree,eax
		.endif

	.endif

	invoke DefWindowProc,hlc_hWin,hlc_uMsg,hlc_wParam,hlc_lParam
	ret

_Hyperlink endp

InitHyperLinkClass proc
	LOCAL hlc_wcx			:WNDCLASSEX

	jmp @F
		UDC_HyperClass	db		"UDC_HyperLink",0
	@@:

	mov hlc_wcx.cbSize,SIZEOF WNDCLASSEX
	mov hlc_wcx.style, CS_HREDRAW or CS_VREDRAW
	mov eax,hInstance
	mov hlc_wcx.hInstance,eax
	mov hlc_wcx.lpszClassName,OFFSET UDC_HyperClass
	mov hlc_wcx.cbClsExtra,0
	mov hlc_wcx.cbWndExtra,36
	mov hlc_wcx.lpfnWndProc,OFFSET _Hyperlink
	mov hlc_wcx.hIcon,NULL
	mov hlc_wcx.hIconSm,NULL
	invoke GetStockObject,NULL_BRUSH
	mov hlc_wcx.hbrBackground,eax
	mov hlc_wcx.lpszMenuName,NULL

	invoke LoadCursor,NULL,IDC_HAND
	mov hlc_wcx.hCursor,eax

	invoke RegisterClassEx,ADDR hlc_wcx
	ret
InitHyperLinkClass endp

AddDriveType proc uses esi ID:DWORD,BUFFER:DWORD
	.if ID==DRIVE_REMOVABLE
		invoke lstrcpy,addr bufferx,BUFFER	
		invoke GetMsgAddr,73
		invoke lstrcat,addr bufferx,eax ;addr szRemovable	
	.elseif ID==DRIVE_FIXED
		invoke GetVolumeInformation,esi,addr buffery,255,0,addr bufferx,0,0,0
		push eax
		invoke lstrcpy,addr bufferx,esi
		invoke lstrcat,addr bufferx,addr separator
		pop eax	
		.if eax	
			invoke lstrcat,addr bufferx,addr buffery
		.endif		
	.elseif ID==DRIVE_REMOTE	
		invoke lstrcpy,addr bufferx,esi	
		invoke GetMsgAddr,76
		invoke lstrcat,addr bufferx,eax ;addr szRemote	
	.elseif ID==DRIVE_CDROM		
		invoke lstrcpy,addr bufferx,esi	
		invoke GetMsgAddr,74
		invoke lstrcat,addr bufferx,eax ;addr szCdrom	
	.elseif ID==DRIVE_RAMDISK	
		invoke lstrcpy,addr bufferx,esi	
		invoke GetMsgAddr,75
		invoke lstrcat,addr bufferx,eax ;addr szRamdisk	
	.endif	
	ret
AddDriveType endp
GetDrives1 proc uses esi ebx ecx
LOCAL drivenames[1024] :byte
LOCAL sfi:SHFILEINFO
		invoke GetLogicalDriveStrings,1023,addr drivenames
		lea esi,drivenames
		mov al,[esi+1]
		.while al!=0
			invoke GetDriveType,esi
			invoke AddDriveType,eax,esi
			invoke SendMessage,hLB1,CB_ADDSTRING,0,addr bufferx
			push eax   ;save index
			mov edi,offset bufferx
			mov byte ptr [edi+3],0
		    INVOKE SHGetFileInfo, addr bufferx, 0, addr sfi, sizeof SHFILEINFO,SHGFI_SYSICONINDEX or SHGFI_SMALLICON ;or SHGFI_TYPENAME or SHGFI_ATTRIBUTES
		    mov ebx,sfi.iIcon
		    pop ecx ;get saved index
			invoke SendMessage,hLB1,CB_SETITEMDATA,ecx,ebx
			invoke lstrlen,esi
			add esi,eax				
			inc esi
			mov al,[esi]
		.endw
		ret
GetDrives1 endp
GetDrives2 proc uses esi ebx ecx
LOCAL drivenames[1024] :byte
LOCAL sfi:SHFILEINFO
		invoke GetLogicalDriveStrings,1023,addr drivenames
		lea esi,drivenames
		mov al,[esi+1]
		.while al!=0
			invoke GetDriveType,esi
			invoke AddDriveType,eax,esi
			invoke SendMessage,hLB2,CB_ADDSTRING,0,addr bufferx
			push eax   ;save index
			mov edi,offset bufferx
			mov byte ptr [edi+3],0
		    INVOKE SHGetFileInfo, addr bufferx, 0, addr sfi, sizeof SHFILEINFO,SHGFI_SYSICONINDEX or SHGFI_SMALLICON ;or SHGFI_TYPENAME or SHGFI_ATTRIBUTES
		    mov ebx,sfi.iIcon
		    pop ecx ;get saved index
			invoke SendMessage,hLB2,CB_SETITEMDATA,ecx,ebx
			invoke lstrlen,esi
			add esi,eax				
			inc esi
			mov al,[esi]
		.endw
		ret
GetDrives2 endp
UpdateStatusBar proc uses edx ecx 
LOCAL buffer1[255] :byte
LOCAL buffer2[255] :byte
				mov isRefresh,0
 				push edi
 				push esi
				; free space
				lea eax,buffer1
                push    eax
                call    FSAC_volume_space
                test    eax, eax
                jz      @@size_ok
                invoke GetMsgAddr,18
                push    eax ;offset str_volsize_fail
                call    logstat
                jmp     @@exit
@@size_ok:
                mov     eax, VolSpace
                xor     edx, edx
                mov     ecx, 400h
                div     ecx
                lea esi,buffer1
                lea edi,buffer2
				invoke dwtoa,eax,esi
				invoke GetMsgAddr,80
                invoke lstrcpy,edi,eax ;addr szFree
                invoke lstrcat,edi,esi
                invoke lstrcat,edi,addr szKb
				invoke SetStatusText, 0, 0, edi		
				; num of files
				push Files_found  ; save files found , keep until smartrefresh complete,then remove!
				;push eax
				;invoke FSAC_search_file
				push offset FileFilter
				call File_Count ;Ex
				;mov Files_found,eax
                lea esi,buffer1
				invoke dwtoa,Files_found,esi
                lea edi,buffer2
				invoke GetMsgAddr,79
   	            invoke lstrcpy,edi,eax ;addr szFiles
       	        invoke lstrcat,edi,esi
				invoke SetStatusText, 2, 0, edi
				pop Files_found
				pop esi
				pop edi
@@exit:			ret
UpdateStatusBar endp
CopyMemory proc uses esi edi ecx , Dest:DWORD, Source:DWORD, mlength:DWORD

; 	This routine is provided in place of Visual C's CopyMemory
;	----------------------------------------------------------

;	It could be developed a little more to move data faster as double words (movsd)
;	but possibly needs checking to ensure we copy the exact number of bytes
;	in the bitmap; this could be an odd number and a possible solution is to
;	copy as many Dwords as possible 1st then any remaining word or byte.
;	Leave this upgrade until later.
;	pusha     	
	cld				; Work upwards

	mov	esi, Source		; Source address
	mov	edi, Dest		; Destination address
	mov	ecx, mlength	; Get size in bytes
	shr	ecx, 1			; Convert to words   

	rep	movsw			; repeat copy util all done
;	popa
	ret

CopyMemory endp
SmartRefreshDel proc uses ebx SMname:DWORD
				;
				; Search filename in mem buffer 
				;
				invoke lstrlen,SMname
				invoke BinSearch,0,SearchBuf_Ptr,SearchBuf_Size,SMname,eax
				.if eax!=-1
					mov ebx,SearchBuf_Ptr
					add eax,ebx
					mov byte ptr [eax],255
				.endif	
				ret
SmartRefreshDel endp
SmartRefreshDelDir proc uses ebx SMname:DWORD
				;
				; Search filename in mem buffer 
				;
				invoke lstrlen,SMname
				invoke BinSearch,0,SearchBuf_Ptr,SearchBuf_Size,SMname,eax
				.if eax!=-1
					mov ebx,SearchBuf_Ptr
					add eax,ebx
					mov byte ptr [eax],255
				.endif	
				ret
SmartRefreshDelDir endp
;SmartRefreshMd proc ; the same as copy
;	ret
;SmartRefreshMd endp
;----------------------------------------
; add 1 record to memory mapped filelist: 
;----------------------------------------
; old:  num of records=P2kLoadFiles , StartAddress=Searchbuf_ptr , FreeOffset
; new:  num of records=+1  ; increase mem buffer with 110h bytes 
; new record content: 4 byte=00000100h,ascii filename,4 byte=attrib,4 byte=size endian?
; new file or overwrite existing ????
SmartRefreshCopy proc uses ecx esi SMname:DWORD,SMsize:DWORD,SMattrib:DWORD
				;
				; check if new file exists with FSAC_open/FSAC_close !
				;
				mov eax,P2kLoadFiles
				mov ecx,P2kRecordSize ;110h ;ppppp
				add ecx,4				;ppppp
				mul ecx
				push eax ; old size
				add eax,P2kRecordSize ;110h ; +1 record ;ppppp
				add eax,4			;ppppp
				; alloc new buffer
				mov SearchBuf_Size,eax
				invoke GlobalAlloc,GMEM_FIXED,eax
				pop ecx  ; old size
				push eax ; addr of new buffer
				invoke CopyMemory,eax,SearchBuf_Ptr,ecx
				invoke GlobalFree,SearchBuf_Ptr
				mov eax,FreeOffset
				push eax
				add eax,P2kRecordSize ;110h		;ppppp
				add eax,4			;ppppp
				mov FreeOffset,eax ; for next time, if refresh not actualize FreeOffset
				pop eax
				;add new record
				pop SearchBuf_Ptr
				add eax,SearchBuf_Ptr
				mov esi,eax ; pos of new record
				mov eax,00000100h  ; 1 db bejegyzés lesz
				mov [esi],eax
				add esi,4
				invoke lstrcpy,esi,SMname  	 ; **** full filename
				mov eax,SMattrib 			 ; **** attrib
				invoke SetAttrib
				;mov [esi+104h],eax  ;ppppp
				mov eax,SMsize 				 ; **** size
				xchg ah,al

				rol eax,10h
				xchg al,ah
				invoke SetSize
				;mov [esi+108h],eax  ;ppppp
				
				inc P2kLoadFiles
				inc Files_found
				inc Row2 ;********
				.if P2kLimit!=-1
					inc P2kLimit
				.endif
				mov isRefresh,1
				ret
SmartRefreshCopy endp
SmartRefreshAttr proc uses ebx ecx SMname:DWORD
				;
				; Search filename in mem buffer 
				;
				invoke lstrlen,SMname
				invoke BinSearch,0,SearchBuf_Ptr,SearchBuf_Size,SMname,eax
				.if eax!=-1
					mov ebx,SearchBuf_Ptr
					add eax,ebx
					mov ecx,Attrib
					mov ebx,Attrib2
					mov bh,cl
					invoke SetAttrib2
					;mov [eax+104h],ebx   ;ppppp
				.endif	
				ret
SmartRefreshAttr endp
;
; Needed for Drag'n Drop / Drop file(s)
;
Paste1 proc  uses esi edi ebx edx hWin:DWORD ; bufferx==source filename
LOCAL buffer1[255] :byte
		mov esi,offset bufferx
		invoke lstrlen,addr bufferx
		add esi,eax
		mov al,[esi]
		.while al !="\"
			dec esi
			mov al,[esi]
		.endw
		lea edi,buffer1
		invoke SendMessage,hHead1,WM_GETTEXT,255,edi
		invoke lstrcat,edi,esi
		invoke ShowWindow,hList1,SW_HIDE
		invoke ShowWindow,hList2,SW_HIDE
		.if Drive1>4 && Drive2>4 ; localcopy
		;.if Drive1!=0 && Drive2!=0 ; localcopy
			;execute localcopy
			invoke CopyFile,addr bufferx,edi,TRUE
			invoke SendMessage,hHead1,WM_GETTEXT,255,addr szDrive1
			invoke SetCurrentDirectory,addr szDrive1

			invoke FillFileInfo1,hWin
			invoke SetFocus,hList1
			invoke ShowWindow,hList1,SW_SHOW
			invoke ShowWindow,hList2,SW_SHOW
		.else ; p2k copy up/down
			.if Drive1<4 && Drive2<4			;p2k<---->p2k spec!!!
			;.if Drive1==0 && Drive2==0			;p2k<---->p2k spec!!!
				nop
			.elseif Drive1<4	;upload
			;.elseif Drive1==0	;upload
						; read file
						invoke CreateFile,addr bufferx,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
						mov	hReadFile,eax
						invoke GetFileSize,hReadFile,addr nBytes
						inc	eax
						mov	nBytes,eax
						invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
						mov	hMemFile,eax
						invoke ReadFile,hReadFile,hMemFile,nBytes,addr nBytes,FALSE
						invoke CloseHandle,hReadFile
						; set target
						invoke SendMessage,hHead1,WM_GETTEXT,255,addr szDrive1
						mov edi,offset szDrive1
						mov al,[edi]
						.while al!="/"	;step to first "/" = cut leading "P2k:"
							inc edi
							mov al,[edi]
						.endw
						inc esi
						invoke lstrcat,edi,esi ; full target path + filename
						mov stay_quiet,1	
;						invoke logstat,edi
						push edi ; save name
						push 4  	;attrib
						push edi 	;name
						invoke FSAC_open
						mov eax,nBytes
						mov edx,0
						mov ebx,1000
						div ebx
						inc eax
						shl eax,16 ; to upper dword
						invoke SendMessage,hBar,PBM_SETRANGE,0,eax
						invoke SendMessage,hBar,PBM_SETSTEP,1,0
						invoke SendMessage,hBar,PBM_SETPOS,0,0
						
						push nBytes ;filesize
						push hMemFile ; ptr to file in mem
						invoke FSAC_write
						invoke FSAC_close  ; upload now works!
						mov stay_quiet,0	
						
						invoke GlobalFree,hMemFile
						
						invoke UpdateStatusBar
						
						pop esi ;recover saved name
						invoke SmartRefreshCopy,esi,nBytes,07000400h
				invoke SetFocus,hList1
				invoke P2kGetFileList1,hWin
				invoke SendMessage,hList1,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc1
				invoke UpdatelParam1
				invoke ShowWindow,hList1,SW_SHOW
				invoke ShowWindow,hList2,SW_SHOW
			.else ; may dload (from p2kc) and may localcopy (from another app)
				nop	
			.endif			
        .endif
        
	ret
Paste1 endp	
Paste2 proc  uses esi edi edx ebx hWin:DWORD ; bufferx==source filename
LOCAL buffer1[255] :byte
			mov esi,offset bufferx
			invoke lstrlen,addr bufferx
			add esi,eax
			mov al,[esi]
			.while al !="\"
				dec esi
				mov al,[esi]
			.endw
			lea edi,buffer1
			invoke SendMessage,hHead2,WM_GETTEXT,255,edi
			invoke lstrcat,edi,esi
			invoke ShowWindow,hList1,SW_HIDE
			invoke ShowWindow,hList2,SW_HIDE
		.if Drive1>4 && Drive2>4 ; localcopy
		;.if Drive1!=0 && Drive2!=0 ; localcopy
			;execute localcopy
			invoke CopyFile,addr bufferx,edi,TRUE
			invoke SendMessage,hHead2,WM_GETTEXT,255,addr szDrive2
			invoke SetCurrentDirectory,addr szDrive2
			invoke FillFileInfo2,hWin
			invoke SetFocus,hList2
			invoke ShowWindow,hList1,SW_SHOW
			invoke ShowWindow,hList2,SW_SHOW
		.else ; p2k copy up/down
			.if Drive1<4 && Drive2<4			;p2k<---->p2k spec!!!
			;.if Drive1==0 && Drive2==0			;p2k<---->p2k spec!!!
				nop
			.elseif Drive2<4	;upload
			;.elseif Drive2==0	;upload
						; read file
						invoke CreateFile,addr bufferx,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
						mov	hReadFile,eax
						invoke GetFileSize,hReadFile,addr nBytes
						inc	eax
						mov	nBytes,eax
						invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
						mov	hMemFile,eax
						invoke ReadFile,hReadFile,hMemFile,nBytes,addr nBytes,FALSE
						invoke CloseHandle,hReadFile
						; set target
						invoke SendMessage,hHead2,WM_GETTEXT,255,addr szDrive2
						mov edi,offset szDrive2
						mov al,[edi]
						.while al!="/"	;step to first "/" = cut leading "P2k:"
							inc edi
							mov al,[edi]
						.endw
						inc esi
						invoke lstrcat,edi,esi ; full target path + filename
						mov stay_quiet,1	
;						invoke logstat,edi
						push edi ; save name
						push 4  	;attrib
						push edi 	;name
						invoke FSAC_open
						mov eax,nBytes
						mov edx,0
						mov ebx,1000
						div ebx
						inc eax
						shl eax,16 ; to upper dword
						invoke SendMessage,hBar,PBM_SETRANGE,0,eax
						invoke SendMessage,hBar,PBM_SETSTEP,1,0
						invoke SendMessage,hBar,PBM_SETPOS,0,0
						
						push nBytes ;filesize
						push hMemFile ; ptr to file in mem
						invoke FSAC_write
						invoke FSAC_close  ; upload now works!
						mov stay_quiet,0	
						
						invoke GlobalFree,hMemFile
						
						invoke UpdateStatusBar
						
						pop esi ;recover saved name
						invoke SmartRefreshCopy,esi,nBytes,07000400h
				invoke SetFocus,hList2
				invoke P2kGetFileList2,hWin
				invoke SendMessage,hList2,LVM_SORTITEMS,FileNameSortOrder,addr CompareFunc2
				invoke UpdatelParam2
				invoke ShowWindow,hList1,SW_SHOW
				invoke ShowWindow,hList2,SW_SHOW
			.else ; may dload (from p2kc) and may localcopy (from another app)
				nop	
			.endif			
        .endif
        
	ret
Paste2 endp	
NewList1Proc proc uses esi edi hWin:HWND,uMsg:UINT,wParam:WPARAM,lParam:LPARAM
	mov eax,uMsg
	.if eax==WM_DROPFILES
        invoke DragQueryFile,wParam,0ffffffffh,ADDR bufferx,128
        mov esi,eax
        dec esi
        .while esi!=-1
	        invoke DragQueryFile,wParam,esi,ADDR bufferx,128
    	    invoke Paste1,hWin
    	    dec esi
    	.endw    
    .elseif eax==WM_CHAR
    	mov eax,wParam
    	.if eax==16h  ; ctrl-V , paste
    		invoke OpenClipboard,hWin
    		invoke GetClipboardData,CF_HDROP

    		mov edi,eax
	        invoke DragQueryFile,edi,0ffffffffh,ADDR bufferx,128
	        mov esi,eax
	        .while esi!=-1
		        invoke DragQueryFile,edi,esi,ADDR bufferx,128
	    	    invoke Paste1,hWin
	    	    dec esi
	    	.endw    
	        invoke CloseClipboard
    	.endif    
	.endif
	invoke CallWindowProc,OldList1WndProc,hWin,uMsg,wParam,lParam
	ret
NewList1Proc endp
NewList2Proc proc uses edi esi hWin:HWND,uMsg:UINT,wParam:WPARAM,lParam:LPARAM
	mov eax,uMsg
	.if eax==WM_DROPFILES
        invoke DragQueryFile,wParam,0ffffffffh,ADDR bufferx,128
        mov esi,eax
        dec esi
        .while esi!=-1
	        invoke DragQueryFile,wParam,esi,ADDR bufferx,128
    	    invoke Paste2,hWin
    	    dec esi
    	.endw    
    .elseif eax==WM_CHAR
    	mov eax,wParam
    	.if eax==16h  ; ctrl-V , paste
    		invoke OpenClipboard,hWin
    		invoke GetClipboardData,CF_HDROP
    		mov edi,eax
	        invoke DragQueryFile,edi,0ffffffffh,ADDR bufferx,128
	        mov esi,eax
	        .while esi!=-1
		        invoke DragQueryFile,edi,esi,ADDR bufferx,128
	    	    invoke Paste2,hWin
	    	    dec esi
	    	.endw    
	        invoke CloseClipboard
    	.endif    
	.endif
	invoke CallWindowProc,OldList2WndProc,hWin,uMsg,wParam,lParam
	ret
NewList2Proc endp
WriteLogFile proc
		push eax
		invoke lstrcpy,addr bufferx,addr LaunchDir
		invoke lstrcat,addr bufferx,StrAddr("\Received_filelist.raw")
		invoke DeleteFile,addr bufferx
		invoke CreateFile,addr bufferx,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0
		mov hSaveFile,eax
		invoke SetFilePointer,hSaveFile,0,0,FILE_END
		;invoke WriteFile,hSaveFile,SearchBuf_Pos,Cmd_Recv_Size,addr writtenb,0
		mov eax,SearchBuf_Pos
		sub eax,SearchBuf_Ptr
		invoke WriteFile,hSaveFile,SearchBuf_Ptr,eax,addr writtenb,0
		invoke CloseHandle,hSaveFile
		pop eax
		ret
WriteLogFile endp		
LoadConfig proc hWin:HWND
	invoke lstrcpy,addr bufferx,addr LaunchDir
	invoke lstrcat,addr bufferx,addr szBackslash
	invoke lstrcat,addr bufferx,addr ConfigName
	invoke CreateFile,offset bufferx,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	.if eax!=INVALID_HANDLE_VALUE
		mov	hSaveFile,eax
		mov eax,23*4 +262 +20+510+24+255+4+255+255+4
		invoke ReadFile,hSaveFile,addr P2kLimit,eax,addr writtenb,FALSE
		.if writtenb!=23*4 +262 +20+510+24+255+4+255+255+4 || P2kLimit!=-1 || isFade!=00
			invoke CloseHandle,hSaveFile
			invoke DeleteFile,addr bufferx
			invoke ShowWindow,hSplash,SW_HIDE
			invoke MessageBox,hWin,StrAddr("Config file corrupted, deleted now! Application will restart."),StrAddr("Warning !!"),MB_SYSTEMMODAL+MB_ICONASTERISK+MB_OK
			mov startInfo.dwFlags,STARTF_USESHOWWINDOW
			mov startInfo.wShowWindow,SW_HIDE
			invoke CreateProcess,NULL,StrAddr("restart"),NULL,NULL,FALSE,\ 
		      NORMAL_PRIORITY_CLASS,\ 
      		  NULL,NULL,ADDR startInfo,ADDR processInfo
      		mov configCorrupted,1  
      		invoke SendMessage,hWnd,WM_CLOSE,0,0  
		.endif
		invoke CloseHandle,hSaveFile
	.else
		invoke ShowWindow,hSplash,SW_HIDE
		invoke MessageBox,hWin,StrAddr ("Config file not found! Defaults loaded."),StrAddr ("Warning!"),MB_SYSTEMMODAL+MB_OK	
	.endif
	ret
LoadConfig endp
LoadPos proc uses edi hWin:HWND			
		invoke LockWindowUpdate,hWin ;less flickering
		invoke LockWindowUpdate,hList1
		invoke LockWindowUpdate,hList2
		invoke LockWindowUpdate,hF2
		invoke LockWindowUpdate,hF3
		invoke LockWindowUpdate,hF4
		invoke LockWindowUpdate,hF5
		invoke LockWindowUpdate,hF6
		invoke LockWindowUpdate,hF7
		invoke LockWindowUpdate,hF8
		invoke LockWindowUpdate,hF9
		invoke LockWindowUpdate,hHead1
		invoke LockWindowUpdate,hHead2
		invoke LockWindowUpdate,hReread2
		invoke LockWindowUpdate,hLB2
		invoke LockWindowUpdate,hBar
		invoke LockWindowUpdate,hLog
		mov edi,offset WinPos
		invoke GetWindowPlacement,hWin,addr WPlacement
		mov eax,[edi]
		mov WPlacement.rcNormalPosition.left,eax
		mov eax,[edi+4]
		mov WPlacement.rcNormalPosition.right,eax 
		mov eax,[edi+8]
		mov WPlacement.rcNormalPosition.top,eax 
		mov eax,[edi+12]
		mov WPlacement.rcNormalPosition.bottom,eax 
		invoke SetWindowPlacement,hWin,addr WPlacement
		invoke LockWindowUpdate,0 ;less flickering
		ret
LoadPos endp		
SaveConfig proc uses edi hWin:HWND
	.if configCorrupted==0
		invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr szDrive1
		invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr szDrive2
		mov edi,offset WinPos
		invoke GetWindowPlacement,hWin,addr WPlacement
		mov eax,WPlacement.rcNormalPosition.left
		mov [edi],eax
		mov eax,WPlacement.rcNormalPosition.right
		mov [edi+4],eax
		mov eax,WPlacement.rcNormalPosition.top
		mov [edi+8],eax
		mov eax,WPlacement.rcNormalPosition.bottom
		mov [edi+12],eax
		invoke lstrcpy,addr bufferx,addr LaunchDir
		invoke lstrcat,addr bufferx,addr szBackslash
		invoke lstrcat,addr bufferx,addr ConfigName
		invoke DeleteFile,offset bufferx
		invoke CreateFile,offset bufferx,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0
		;.if eax==INVALID_HANDLE_VALUE
		;.endif	
		mov hSaveFile,eax
		mov eax,23*4 +262+20+510+24+255+4+255+255+4 ;11*4  ;7*4  ;config size 
		invoke WriteFile,hSaveFile,addr P2kLimit,eax,addr writtenb,0
		invoke CloseHandle,hSaveFile
	.endif	
	ret
SaveConfig endp
SetP2kRecordSize proc uses esi ebx edx
	push eax
	mov esi,SearchBuf_Pos
	mov eax,Cmd_Recv_Size
	sub eax,4
	mov ebx,[esi]
	xchg bh,bl
	mov edx,0
	div bx
	mov P2kRecordSize,eax
	sub eax,4
	mov P2kSizeOffset,eax
	sub eax,4
	mov P2kAttribOffset,eax
	pop eax
	ret
SetP2kRecordSize endp
GetP2kSize proc
	push esi
	add esi,P2kSizeOffset
	mov eax,[esi]
	pop esi
	ret
GetP2kSize endp
GetAttrib proc
	push esi
	add esi,P2kAttribOffset
	mov eax,[esi]
	.if isUSBLAN==3
		xchg al,ah
	.endif
	pop esi
	ret
GetAttrib endp
SetSize proc
	push esi
	add esi,P2kSizeOffset
	mov [esi],eax
	pop esi
	ret
SetSize endp
SetAttrib proc
	push esi
	add esi,P2kAttribOffset
	mov [esi],eax
	pop esi
	ret
SetAttrib endp
SetAttrib2 proc
	push eax
	add eax,P2kAttribOffset
	mov [eax],ebx
	pop eax
	ret
SetAttrib2 endp
SaveLog proc uses edi esi hWin:HWND
	invoke lstrcpy,addr bufferx,addr LaunchDir
	invoke lstrcat,addr bufferx,addr szBackslash
	invoke lstrcat,addr bufferx,addr LogName
	invoke DeleteFile,offset bufferx
	invoke CreateFile,offset bufferx,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0
	mov hSaveFile,eax
	invoke SendDlgItemMessage,hWin,1001,LB_GETCOUNT,0,0
	mov esi,eax
	mov edi,0
	.while edi!=esi
		push edi
		invoke SendDlgItemMessage,hWin,1001,LB_GETTEXT,edi,addr bufferx
		invoke lstrlen,addr bufferx
		;invoke SendDlgItemMessage,hWin,1001,LB_GETTEXTLEN,edi,0
		invoke WriteFile,hSaveFile,addr bufferx,eax,addr writtenb,0
		invoke WriteFile,hSaveFile,addr crlf,2,addr writtenb,0
		pop edi
		inc edi
	.endw	
	invoke CloseHandle,hSaveFile
	ret
SaveLog endp
P2kGetFileListHW	proc uses esi ecx 
LOCAL Row:DWORD
LOCAL lvi:LV_ITEM
LOCAL lvc:LV_COLUMN 
LOCAL sfi:SHFILEINFO
LOCAL buffer[256]:BYTE

					mov isThreadComplete,0
					mov FreeOffset,0
					invoke GetTickCount
					mov StartTicks,eax
					;invoke ShowWindow,hList1,SW_HIDE
					;invoke ShowWindow,hList2,SW_HIDE
					;mov isHide,1
					
					;invoke SetClassLong,hWin,GCL_HCURSOR,hWaitCursor
					;nop
					
					mov eax,[SearchBuf_Ptr]
					mov [SearchBuf_Pos],eax
					;push eax
					.if isRefresh==1
						invoke GlobalFree,SearchBuf_Ptr
					.elseif isRefresh==5
						mov isRefresh,1	
					.endif
					;push eax
					;invoke FSAC_search_file
					;mov eax,Files_found
				push offset FileFilter
				call File_Count ;Old Ex
				mov eax,Files_found
				;	mov [P2kLoadFiles],eax
					inc eax
					shl eax,16
					invoke SendMessage,hBar,PBM_SETRANGE,0,eax
					invoke SendMessage,hBar,PBM_SETSTEP,1,0
					invoke SendMessage,hBar,PBM_SETPOS,0,0
					invoke dwtoa,Files_found,addr bufferx
                	invoke GetMsgAddr,23
					invoke lstrcat,addr bufferx,eax; addr str_Files_Added
					invoke logstat,addr bufferx
					invoke logstat,addr bufferx
					
;					invoke dwtoa,Files_found,addr buffery
;    	            invoke lstrcpy,addr bufferx,addr szFiles
;        	        invoke lstrcat,addr bufferx,addr buffery
;					invoke SetStatusText, 2, 0, ADDR bufferx
					
					mov stay_quiet,1
					mov Row2,0
	                mov     word ptr Cmd_Recv_Buf, -1
	                mov     dword ptr Cmd_Send_Buf, 08000000h ; Cmd
	                mov eax,is3g
	                mov byte ptr Cmd_Send_Buf+4,al ;3 ;1 ; extra byte snipped from mck
	                push    offset Cmd_Recv_Size
	                push    SearchBuf_Pos
	                mov eax,4
	                .if is3g!=0
	                	mov eax,5
	                .endif
	                push    eax ;5 ;4				 ; size is 5 instead 4 , snipped from mck
	                push    offset Cmd_Send_Buf
	                push    004Ah                   ; FSAC

	                call    P2K_SendCommand
	                
	                invoke SetP2kRecordSize
					.while eax==0 ;<Files_found ;testfilenum ;.while eax==0 
						mov esi,SearchBuf_Pos	; elsõ 4 byte=hány record?
						mov eax,[esi]	
						xchg al,ah				; e398=3
						add esi,4
						add FreeOffset,4
						mov ecx,eax
						.BREAK .if eax==0  ; if zero filename blocks received
						.while ecx!=0
							push ecx
							mov stay_quiet,0
							invoke logstat2,esi
							mov stay_quiet,1
							; DIAG & EXPLORE P2K FILE RECORD STRUCTURE
							;mov eax,[esi+100h]
							;mov ebx,[esi+105h] ; attrib
							;mov ecx,[esi+108h] ; size
							;mov edx,[esi+10ch] ; next name
							inc Row2
							invoke SendMessage,hBar,PBM_STEPIT,0,0
							mov eax,P2kRecordSize
							add esi,eax ;10ch	;ppppp
							add FreeOffset,eax ;10ch	;ppppp
							pop ecx
							dec ecx
							
						.endw
						mov eax,Row2
					.BREAK .if eax>P2kLimit	
						mov eax,[SearchBuf_Pos]
						add eax,[Cmd_Recv_Size]
						mov [SearchBuf_Pos],eax
		                mov     word ptr Cmd_Recv_Buf, -1
		                mov     dword ptr Cmd_Send_Buf, 08000000h ; Cmd
		                mov eax,is3g

		                mov byte ptr Cmd_Send_Buf+4,al   ;3 ;1 ; extra byte snipped from mck

		                push    offset Cmd_Recv_Size
		                push    SearchBuf_Pos
		                mov eax,4
		                .if is3g!=0
		                	mov eax,5
		                .endif
		                push    eax ;5 ;4
		                push    offset Cmd_Send_Buf
		                push    004Ah                   ; FSAC
		                call    P2K_SendCommand
		                
		                
		                
			        .endw
					push Row2	;betöltött filek
					pop Files_found
					push Row2	;betöltött filek
					pop P2kLoadFiles
			        
	                .if isUSBLAN==3
	                	; statusbar filecount
						invoke dwtoa,Files_found,addr buffery
						invoke GetMsgAddr,79
		   	            invoke lstrcpy,addr bufferx,eax ;addr szFiles
		       	        invoke lstrcat,addr bufferx,addr buffery
						invoke SetStatusText, 2, 0, ADDR bufferx
	                	; get hidden files list
	                	.if hMemHiddenF!=0
	                		invoke GlobalFree,hMemHiddenF
	                		invoke GlobalFree,hMemHiddenFPtrs
	                	.endif
	                	invoke ReadHiddenList,hWnd
	                	mov ecx,nHiddenFCount
	                	mov esi,offset hMemHiddenFPtrs
                		mov eax,[esi]
	                	.while ecx!=0
	                		pusha
	                		invoke SmartRefreshCopy,[eax],99999999,0
	                		popa
							add eax,4
							dec ecx
	                	.endw	
	                .endif	

					mov P2kReady,1
					mov stay_quiet,0
					invoke dwtoa,Row2,addr bufferx ;P2kLoadFiles,addr bufferx
                	invoke GetMsgAddr,40
					invoke lstrcat,addr bufferx,eax ;addr szFilenamesLoaded 
					invoke GetTickCount
					sub eax,StartTicks
					mov StartTicks,eax
					invoke dwtoa,StartTicks,addr buffery 
					invoke lstrcat,addr bufferx,addr buffery 
                	invoke GetMsgAddr,41
					invoke lstrcat,addr bufferx,eax ;addr szSeconds 
					invoke logstat2,addr bufferx
					;invoke ShowWindow,hList1,SW_SHOW


					;invoke ShowWindow,hList2,SW_SHOW
					mov isHide,0
					mov isThreadComplete,1
	                .if isVerboseLog==1
	                	invoke WriteLogFile ;**********
	                .endif
	                ;invoke P2K_Vibrate
					ret
P2kGetFileListHW	endp
P2kDownloadHW		proc 	uses edx ebx
					mov isThreadComplete,0
					push AttribHW ;eax
					push NameHW ;esi
					invoke FSAC_open
					push 0
					push 0
					invoke FSAC_seek
					
					mov eax,P2kFilesize
					mov edx,0
					mov ebx,1000
					div ebx
					inc eax
					shl eax,16 ; to upper dword
					invoke SendDlgItemMessage,hWnd,1014,PBM_SETRANGE,0,eax
					invoke SendDlgItemMessage,hWnd,1014,PBM_SETSTEP,1,0
					invoke SendDlgItemMessage,hWnd,1014,PBM_SETPOS,0,0
					
					push P2kFilesize
					push hMemFile
					invoke FSAC_read
					invoke FSAC_close
					mov isThreadComplete,1
					ret
P2kDownloadHW		endp
P2kUploadHW			proc uses edx ebx
					mov isThreadComplete,0
					push 4  	;attrib
					push NameHW ;esi 	;name
					invoke FSAC_open
					;
					; if failed maybe folder not present
					;
					.if eax==-1
						;
						; try to create folders listed in path
						;
						mov esi,NameHW
						mov edi,esi
						invoke lstrlen,esi
						add edi,eax
						inc esi
						.while esi<edi
							.while byte ptr [esi]!="/" && esi!=edi 
								inc esi
							.endw
							mov byte ptr [esi],0
							; make folder
							.if edi!=esi
								push esi
								push edi
								push 4h
								push NameHW
								invoke FSAC_makedir
								pop edi
								pop esi
								mov byte ptr [esi],"/"
							.endif	
							inc esi
						.endw
						; retry open file
						push 4  	;attrib
						push NameHW ;esi 	;name
						invoke FSAC_open
					.endif
					mov eax,nBytes
					mov edx,0
					mov ebx,1000
					div ebx
					inc eax
					shl eax,16 ; to upper dword
					invoke SendMessage,hBar,PBM_SETRANGE,0,eax
					invoke SendMessage,hBar,PBM_SETSTEP,1,0
					invoke SendMessage,hBar,PBM_SETPOS,0,0
					
					push nBytes ;filesize
					push hMemFile ; ptr to file in mem
					invoke FSAC_write
					invoke FSAC_close  ; upload now works!
					mov isThreadComplete,1
					ret
P2kUploadHW			endp
;
; Auto-zoom on mousehover
;
LVProc		 PROC uses ebx h2:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
LOCAL lvi:LV_ITEM
LOCAL lvc:LV_COLUMN
LOCAL buffer[256]	:BYTE
LOCAL numbuf[56]	:BYTE
			mov eax,uMsg
			.if eax==WM_MOUSEMOVE
				;
				; Grow LV
				;
				mov eax,LVHoverSizeY
				mov ListPlacement1.rcNormalPosition.bottom,eax
				invoke SetWindowPlacement,hList1,addr ListPlacement1
				; shrink LB
				mov eax,LBOriginalSizeY
				mov LogPlacement.rcNormalPosition.top,eax
				invoke SetWindowPlacement,hLog,addr LogPlacement
			.endif
			invoke CallWindowProc, OldLVProc, h2, uMsg, wParam, lParam
			ret		
LVProc 	endp
;
; Auto-zoom on mousehover
;
LBProc		 PROC uses ebx h2:DWORD,uMsg:DWORD,wParam:DWORD,lParam:DWORD
LOCAL lvi:LV_ITEM
LOCAL lvc:LV_COLUMN
LOCAL buffer[256]	:BYTE
LOCAL numbuf[56]	:BYTE
			mov eax,uMsg
			.if eax==WM_MOUSEMOVE
				;
				; Grow LB
				;
				mov eax,LBHoverSizeY
				mov LogPlacement.rcNormalPosition.top,eax
				invoke SetWindowPlacement,hLog,addr LogPlacement
				;
				; shrink LV
				;
				mov eax,LVOriginalSizeY
				mov ListPlacement1.rcNormalPosition.bottom,eax
				invoke SetWindowPlacement,hList1,addr ListPlacement1
			.endif
			invoke CallWindowProc, OldLBProc, h2, uMsg, wParam, lParam
			ret		
LBProc 	endp
P2kCopy_down proc uses esi edi Item:DWORD,hWin:DWORD,hSource:DWORD,hDest:DWORD
; hSource and hDest are one of hList1 and hList2
; if hDest is neither it is address of target path directly 
LOCAL lvi:LV_ITEM
LOCAL buffer[512]	:BYTE
LOCAL buffer2[512]	:BYTE
LOCAL buffound:DWORD
						mov eax,Item
						mov lvi.iItem,eax
						mov CurrentItem,eax
						mov lvi.iSubItem,0
						mov lvi.imask,LVIF_TEXT
						lea eax,buffer
						mov lvi.pszText,eax
						mov lvi.cchTextMax,256
						; get the source item
						invoke SendMessage,hSource,LVM_GETITEM,0,addr lvi    ; buffer:filename
						invoke lstrcpy,addr bufferx,addr buffer ; save filename
						mov eax,hSource
						.if eax==hList1
							invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr szDrive1
						.else	
							invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr szDrive2
						.endif	
						invoke lstrcpy,addr bufferx,addr buffer		   
						mov eax,hSource
						.if eax==hList1
							mov esi,offset szDrive1
						.else	
							mov esi,offset szDrive2
						.endif	
						mov al,[esi]
						.while al!="/"	;step to first "/" = cut leading "P2k:"
							inc esi
							mov al,[esi]
						.endw
						; esi=folders
						invoke lstrcat,esi,addr buffer
						; esi=the full source path
						mov lvi.iSubItem,1		; get filesize
						invoke SendMessage,hSource,LVM_GETITEM,0,addr lvi
						invoke logstat,esi
						;
						; check if source is folder
						;
						lea edi,buffer
						.if byte ptr [edi]!="<"
							;
							; just 1 file
							;
							push esi
							invoke atodw,addr buffer
							mov P2kFilesize,eax
							add eax,10
							invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
							mov	hMemFile,eax
							mov lvi.iSubItem,2		; get fileattrib
							invoke SendMessage,hSource,LVM_GETITEM,0,addr lvi
							lea esi,buffer
							add esi,3
							invoke htodw,esi
							pop esi
							mov NameHW,esi
							mov AttribHW,eax
							invoke CreateThread,0,0,addr P2kDownloadHW,0,0,0
							invoke DialogBoxParam,hInstance, 1700,hWin,OFFSET WaitProc,NULL
							;
							; get dest filename
							;
							mov eax,hDest
							.if eax==hList2
								invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr szDrive2
								invoke lstrcat,addr szDrive2,addr szBackslash
								invoke lstrcat,addr szDrive2,addr bufferx ;dest filename+path
							.elseif eax==hList1
								invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr szDrive2
								invoke lstrcat,addr szDrive2,addr szBackslash
								invoke lstrcat,addr szDrive2,addr bufferx ;dest filename+path
							.else
								; Dest is neither drop file to temp folder 
								invoke lstrcpy,addr szDrive2,hDest
								invoke lstrcat,addr szDrive2,addr bufferx ;dest filename+path
							.endif			
							invoke logstat,addr szDrive2
							; save file
							invoke DeleteFile,addr szDrive2
							invoke CreateFile,addr szDrive2,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0
							mov hSaveFile,eax
							invoke SetFilePointer,hSaveFile,0,0,FILE_END
							invoke WriteFile,hSaveFile,hMemFile,P2kFilesize,addr writtenb,0
							invoke CloseHandle,hSaveFile														
							invoke GlobalFree,hMemFile
						.else
							;
							; folder !!!, folder name with full path is in esi, and buffer2
							;
							push SearchBuf_Ptr  ; starting point
							pop SearchBuf_Pos   ; running pointer
							;
							; loop files in searchbuf
							;
							invoke lstrcpy,addr buffer2,esi
							mov buffound,0
							mov eax,buffound
							.while eax<SearchBuf_Size
								invoke lstrlen,addr buffer2
								invoke BinSearch,buffound,SearchBuf_Pos,SearchBuf_Size,addr buffer2,eax
								.if eax!=-1
									mov buffound,eax
									mov esi,SearchBuf_Pos
									add esi,eax
									inc buffound
									;
									; do downloads 
									;
									invoke logstat,esi
									; read file with P2kDownloadHW
									invoke GetP2kSize
								    xchg    ah, al
								    rol     eax,10h
								    xchg    ah,al
									mov P2kFilesize,eax
									pusha 
									add eax,10
									invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
									mov	hMemFile,eax
									invoke GetAttrib
									mov NameHW,esi
									mov AttribHW,eax
									invoke CreateThread,0,0,addr P2kDownloadHW,0,0,0
									invoke DialogBoxParam,hInstance, 1700,hWin,OFFSET WaitProc,NULL
									popa
									; create dest filename
									mov eax,hDest
									.if eax==hList2
										invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr szDrive2
										invoke lstrcat,addr szDrive2,addr szBackslash
									.elseif eax==hList1
										invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr szDrive2
										invoke lstrcat,addr szDrive2,addr szBackslash
									.endif
									invoke InString,1,esi,addr bufferx
									mov edi,esi
									add edi,eax
									dec edi
									invoke lstrcat,addr szDrive2,edi
									; replace all "/" with "\"
									lea esi,szDrive2
									.while byte ptr [esi]!=0
										.if byte ptr [esi]=="/"
											mov byte ptr [esi],"\"
										.endif
										inc esi
									.endw
									invoke logstat,addr szDrive2
									pusha
									;
									; skip if source is a folder (juix phones)
									;
									mov esi,NameHW
									invoke GetAttrib
									and eax,1000h
									.if eax!=1000h
										; create target directory
										lea esi,szDrive2
										invoke lstrlen,esi
										add esi,eax
										.while byte ptr [esi]!="\"
											dec esi
										.endw
										mov byte ptr [esi],0
										push esi
										invoke DeleteFile,addr szDrive2
										invoke CreateDirectory,addr szDrive2,NULL
										pop esi
										mov byte ptr [esi],"\"
										; write file
										invoke CreateFile,addr szDrive2,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0
										mov hSaveFile,eax
										invoke WriteFile,hSaveFile,hMemFile,P2kFilesize,addr writtenb,0
										invoke CloseHandle,hSaveFile
										invoke GlobalFree,hMemFile
									.else
										; 
										; folder itself create it! (juix)
										;	
										push esi
										invoke DeleteFile,addr szDrive2
										invoke CreateDirectory,addr szDrive2,NULL
										pop esi
									.endif
									popa
								.else 
									.break	
								.endif
							.endw
						.endif		
						ret
P2kCopy_down endp
P2kCopy_up proc uses esi Item:DWORD,hWin:DWORD,hSource:DWORD,hDest:DWORD
; hSource and hDest are one of hList1 and hList2
; if hSource is neither it is address of source path directly 
LOCAL lvi:LV_ITEM
LOCAL buffer[512]	:BYTE
LOCAL buffer2[512]	:BYTE
						mov lvi.iItem,eax
						mov CurrentItem,eax
						mov lvi.iSubItem,1 ; get filesize
						mov lvi.imask,LVIF_TEXT
						lea eax,buffer
						mov lvi.pszText,eax
						mov lvi.cchTextMax,256
						; get the source item
						invoke SendMessage,hSource,LVM_GETITEM,0,addr lvi    ; buffer:filename
						;
						; check if source is folder
						;
						lea edi,buffer
						.if byte ptr [edi]!="<"
							mov lvi.iSubItem,0		; get filename
							invoke SendMessage,hSource,LVM_GETITEM,0,addr lvi
							mov eax,hSource
							.if eax==hList1
								invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr szDrive1
								invoke SetCurrentDirectory,addr szDrive1
								invoke CreateFile,addr buffer,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
							.elseif eax==hList2
								invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr szDrive2
								invoke SetCurrentDirectory,addr szDrive2
								invoke CreateFile,addr buffer,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
							.else
								; copy filename to buffer
								lea esi,buffer
								mov edi,hSource
								invoke lstrlen,edi
								add edi,eax
								.while byte ptr[edi]!="\"
									dec edi
								.endw
								inc edi
								invoke lstrcpy,esi,edi
								;invoke logstat,hSource
								invoke CreateFile,hSource,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
							.endif		
							;read file
							mov	hReadFile,eax
							invoke GetFileSize,hReadFile,addr nBytes
							inc	eax
							mov	nBytes,eax
							invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
							mov	hMemFile,eax
							invoke ReadFile,hReadFile,hMemFile,nBytes,addr nBytes,FALSE
							invoke CloseHandle,hReadFile
							; get dest filename
							mov eax,hDest
							.if eax==hList2
								invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr szDrive2
								mov esi,offset szDrive2
							.else
								invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr szDrive1
								mov esi,offset szDrive1
							.endif		
							mov al,[esi]
	
							.while al!="/"	;step to first "/" = cut leading "P2k:"
								inc esi
								mov al,[esi]
							.endw
							invoke lstrcat,esi,addr buffer
							
							invoke lstrcpy,addr bufferx,addr buffer
							invoke lstrcpy,addr DestDir,esi
							.if isTargetOverride==1
								invoke DialogBoxParam,hInstance, 1300,hWin,OFFSET DlgF5Proc,NULL
							.endif
							mov esi,offset DestDir
							push esi ; save name
	
							mov NameHW,esi
							mov AttribHW,eax
							invoke CreateThread,0,0,addr P2kUploadHW,0,0,0
							invoke DialogBoxParam,hInstance, 1700,hWin,OFFSET WaitProc,NULL
							
							invoke GlobalFree,hMemFile
							
							invoke UpdateStatusBar
							
							pop esi ;recover saved name
							invoke SmartRefreshCopy,esi,nBytes,07000400h
						.else
							;
							; folder !!!
							;
							mov lvi.iSubItem,0		; get filename
							invoke SendMessage,hSource,LVM_GETITEM,0,addr lvi
							mov eax,hSource
							.if eax==hList1
								invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr szDrive1
								invoke SetCurrentDirectory,addr szDrive1
							.elseif eax==hList2
								invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr szDrive2
								invoke SetCurrentDirectory,addr szDrive2
							.endif
							;
							; generate filelist of source folder
							;
					    	invoke lstrcpy,addr CmdList,addr CmdListTemp
					    	invoke lstrcat,addr CmdList,addr buffer
					    	invoke lstrcat,addr CmdList,addr CmdListTemp2
					    	invoke lstrcat,addr CmdList,addr LaunchDir
					    	invoke lstrcat,addr CmdList,addr Cmdlist
					    	invoke lstrcat,addr CmdList,addr szQ
							mov startInfo.dwFlags,STARTF_USESHOWWINDOW
							mov startInfo.wShowWindow,SW_HIDE
							invoke CreateProcess,NULL,addr CmdList,addr procAttr ,NULL,FALSE,\ 
					              NORMAL_PRIORITY_CLASS,\ 
					              NULL,NULL,ADDR startInfo,ADDR processInfo
					        invoke WaitForSingleObject,processInfo.hProcess,INFINITE
					        invoke CloseHandle,processInfo.hProcess      
					        invoke CloseHandle,processInfo.hThread
					        ; read filelist
					        invoke ReadFileList,hWin
							; get dest filename
							mov eax,hDest
							.if eax==hList2
								invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr szDrive2
								mov esi,offset szDrive2
							.else
								invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr szDrive1
								mov esi,offset szDrive1
							.endif		
							mov al,[esi]
	
							.while al!="/"	;step to first "/" = cut leading "P2k:"
								inc esi
								mov al,[esi]
							.endw
							;
							; esi == target folder with ending "/"
							;
							; loop source files and upload them
							;
							mov ecx,nFileCount
							mov edi,hMemFilePtrs
							.while ecx!=0
								push ecx
								push edi
								push esi
								invoke lstrcpy,addr buffer2,esi
								; get source filename in [edi]
								invoke logstat,[edi]
								; read file content into hMemFile
								invoke CreateFile,[edi],GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
								mov	hReadFile,eax
								invoke GetFileSize,hReadFile,addr nBytes
								inc	eax
								mov	nBytes,eax
								invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
								mov	hMemFile,eax
								invoke ReadFile,hReadFile,hMemFile,nBytes,addr nBytes,FALSE
								invoke CloseHandle,hReadFile
								; create destination with full path, target folder == esi
								invoke InString,1,[edi],addr buffer
								dec eax
								mov edx,[edi]
								add edx,eax
								invoke lstrcat,addr buffer2,edx
								; replace all "\" with "/"
								lea esi,buffer2
								.while byte ptr [esi]!=0
									.if byte ptr [esi]=="\"
										mov byte ptr [esi],"/"
									.endif
									inc esi
								.endw
								; upload with P2kUploadHW
								lea esi,buffer2
								mov NameHW,esi
								mov AttribHW,eax
								invoke logstat,esi
								invoke CreateThread,0,0,addr P2kUploadHW,0,0,0
								invoke DialogBoxParam,hInstance, 1700,hWin,OFFSET WaitProc,NULL
								invoke GlobalFree,hMemFile
								invoke UpdateStatusBar
								pop esi
								pop edi
								add edi,4
								pop ecx
								dec ecx
							.endw
						.endif		
						ret
P2kCopy_up endp
P2kSeem_down proc uses esi Item:DWORD,hWin:DWORD,hSource:DWORD,hDest:DWORD
; hSource and hDest are one of hList1 and hList2
; if hDest is neither it is address of target path directly 
LOCAL lvi:LV_ITEM
LOCAL buffer[256]	:BYTE
						mov lvi.iItem,eax
						mov CurrentItem,eax
						mov lvi.iSubItem,0
						mov lvi.imask,LVIF_TEXT
						lea eax,buffer
						mov lvi.pszText,eax
						mov lvi.cchTextMax,256
						; get the item
						invoke SendMessage,hSource,LVM_GETITEM,0,addr lvi    ; buffer:filename
						mov eax,hDest
						.if eax==hList2
							invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr szDrive2
							invoke lstrcpy,addr bufferx,addr szDrive2
						.elseif eax==hList1
							invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr szDrive1
							invoke lstrcpy,addr bufferx,addr szDrive1
						.else ; temp	
						.endif		
						;
						; check if item is folder
						;
						invoke lstrlen,addr buffer
						.if eax!=4
							;
							; just 1 seem
							;
							invoke lstrcat,addr bufferx,addr szBackslash
							invoke lstrcat,addr bufferx,addr buffer  ; bufferx == target filename to save seem
							invoke lstrcpy,addr buffery,StrAddr("Download seem: ")
							invoke lstrcat,addr buffery,addr buffer
							invoke logstat,addr buffery
							; read seem
					        push    offset seem_data
				            push    0
				            push    0
							; get numbers
							lea esi,buffer
							mov byte ptr [esi+4],0
							mov byte ptr [esi+9],0
							add esi,5
							invoke htodw,esi ; seem rec
							push eax
							sub esi,5
							invoke htodw,esi ; seem num
							push eax
					        ;push    Item
				            ;push    Seemname
				            invoke Cmd_RDELEM
							; save seem
							invoke DeleteFile,addr bufferx ;savename
							invoke CreateFile,addr bufferx,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0
							mov hSaveFile,eax
							invoke SetFilePointer,hSaveFile,0,0,FILE_BEGIN
							mov eax,offset seem_data
							inc eax
							mov ecx,seem_read_bytes
							dec ecx
							invoke WriteFile,hSaveFile,eax,ecx,addr writtenb,0
							invoke CloseHandle,hSaveFile
						.else
							;
							; folder !!!
							;
							; rec==1 is always valid
							mov stay_quiet,1
							invoke htodw,addr buffer
							mov SeemNum,eax
							mov SeemRec,1
							invoke lstrcat,addr bufferx,addr szBackslash
							invoke lstrcpy,addr buffery,addr bufferx
							mov eax,1
							.while eax!=-1
								mov SeemRec,eax
								invoke lstrcat,addr bufferx,addr buffer  ; bufferx == target filename to save seem
								invoke lstrcat,addr bufferx,StrAddr("_")
								invoke dw2hex,SeemRec,addr bufferz
								invoke lstrcat,addr bufferx,addr bufferz+4
								invoke lstrcat,addr bufferx,StrAddr(".seem")
								invoke Save1Seem
								invoke lstrcpy,addr bufferx,addr buffery
								invoke FindP2kSeem
							.endw 
							mov stay_quiet,0
						.endif		
						ret
P2kSeem_down endp
P2kSeem_up proc uses esi Item:DWORD,hWin:DWORD,hSource:DWORD,hDest:DWORD
; hSource and hDest are one of hList1 and hList2
LOCAL lvi:LV_ITEM
LOCAL buffer[256]	:BYTE

						mov lvi.iItem,eax
						mov CurrentItem,eax
						mov lvi.iSubItem,0
						mov lvi.imask,LVIF_TEXT

						lea eax,buffer
						mov lvi.pszText,eax
						mov lvi.cchTextMax,256
						; get the item
						invoke SendMessage,hSource,LVM_GETITEM,0,addr lvi    ; buffer:filename
						invoke lstrcpy,addr buffery,StrAddr("Upload seem: ")
						invoke lstrcat,addr buffery,addr buffer
						invoke logstat,addr buffery
						; check numbers
						invoke lstrcpy,addr bufferx,addr buffer
						mov esi,offset bufferx
						mov byte ptr [esi+4],0
						mov byte ptr [esi+9],0
						add esi,5
						invoke htodw,esi ; seem rec
						push eax
						sub esi,5
						invoke htodw,esi ; seem num
						pop ebx
						.if eax>0 && eax<2ffh && ebx>0 && ebx<0ffh
							push eax
							push ebx
							mov eax,hSource
							.if eax==hList1
								invoke SendDlgItemMessage,hWin,1016,WM_GETTEXT,255,addr szDrive1
								invoke SetCurrentDirectory,addr szDrive1
							.else
								invoke SendDlgItemMessage,hWin,1015,WM_GETTEXT,255,addr szDrive2
								invoke SetCurrentDirectory,addr szDrive2
							.endif	
							;read file
							invoke CreateFile,addr buffer,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
							mov	hReadFile,eax
							invoke GetFileSize,hReadFile,addr nBytes
							inc	eax
							mov	nBytes,eax
							invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,eax
							mov	hMemFile,eax
							invoke ReadFile,hReadFile,hMemFile,nBytes,addr nBytes,FALSE
							invoke CloseHandle,hReadFile
							; upload seem
							pop ebx ; rec
							pop eax ; num
							push eax
							push ebx
				            push    offset seem_data
				            push    0
					        push    0
						    push    ebx ;seem_rec
				    		push    eax ;seem_num
				    		invoke Cmd_RDELEM
				    		pop ebx
				    		pop eax
				    		dec     seem_read_bytes
							push 	hMemFile
				            push    seem_read_bytes ;bytes=filesize
					        push    0
						    push    ebx ;seem_rec
				    		push    eax ;seem_num
				    		call Seem_Write
							
							invoke GlobalFree,hMemFile
						.else
							invoke MessageBox,hWin,StrAddr("Invalid seem filename! Must be: xxxx_yyyy.seem"),StrAddr("Warning!"),MB_OK	
						.endif
						ret	
P2kSeem_up endp
FindP2kSeem proc uses esi
; Globals: SeemNum
; return next rec or -1 if not found
				mov eax,SeemRec
				inc eax
		        push    offset seem_data
	            push    1
	            push    0
		        push    eax
	            push    SeemNum
	            invoke Cmd_RDELEM
				.if eax==0 ; present
					mov eax,SeemRec
					inc eax
				.else
					mov eax,-1
				.endif
				ret
FindP2kSeem endp
Save1Seem proc
			; read seem
	        push    offset seem_data
            push    0
            push    0
			; get numbers
			push SeemRec
			push SeemNum
            invoke Cmd_RDELEM
			; save seem
			invoke DeleteFile,addr bufferx ;savename
			invoke CreateFile,addr bufferx,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0
			mov hSaveFile,eax
			invoke SetFilePointer,hSaveFile,0,0,FILE_BEGIN
			mov eax,offset seem_data
			inc eax
			mov ecx,seem_read_bytes
			dec ecx
			invoke WriteFile,hSaveFile,eax,ecx,addr writtenb,0
			invoke CloseHandle,hSaveFile
			ret
Save1Seem endp
FindP2kFile proc uses esi Item:DWORD
		mov edi,Item
		mov eax,0
		ret
FindP2kFile endp
FindUSBLAN proc
		; check if usblan already present
		;invoke logstat,addr CmdInsFtpDrive
		;invoke logstat,addr CmdDelIp
		;invoke logstat,addr CmdIp
		mov startInfo.dwFlags,STARTF_USESHOWWINDOW
		mov startInfo.wShowWindow,SW_HIDE
		invoke CreateProcess,NULL,addr CmdInsFtpDrive,NULL,NULL,FALSE,\ 
              NORMAL_PRIORITY_CLASS,\ 
              NULL,NULL,ADDR startInfo,ADDR processInfo
		mov startInfo.wShowWindow,SW_SHOW
		mov startInfo.dwFlags,STARTF_USESHOWWINDOW
		mov startInfo.wShowWindow,SW_HIDE
		invoke CreateProcess,NULL,addr CmdDelIp,NULL,NULL,FALSE,\ 
              NORMAL_PRIORITY_CLASS,\ 
              NULL,NULL,ADDR startInfo,ADDR processInfo
		mov startInfo.wShowWindow,SW_SHOW
		mov startInfo.dwFlags,STARTF_USESHOWWINDOW
		mov startInfo.wShowWindow,SW_HIDE
		invoke CreateProcess,NULL,addr CmdIp,NULL,NULL,FALSE,\ 
              NORMAL_PRIORITY_CLASS,\ 
              NULL,NULL,ADDR startInfo,ADDR processInfo
		mov startInfo.wShowWindow,SW_SHOW
		invoke Sleep,400
		.if AlreadyMapped==0
			invoke ReadIpFile,hWnd
		.endif	
		ret
FindUSBLAN endp
HexAddr:
	push	ecx
	mov		ecx,8
  @@:
	call	Nybble
	mov		[edi],dl
	inc		edi
	dec		ecx
	jne		@b
	mov		[edi],cl
	pop		ecx
	retn

HexByte:
	mov		al,[esi+ebx]
	shl		eax,24
	call	Nybble
	mov		[edi],dl
	inc		edi
	call	Nybble
	mov		[edi],dl
	inc		edi
	inc		ecx
	inc		ebx
	.if ecx==8
		mov		word ptr [edi],'-'
	.else
		mov		word ptr [edi],' '
	.endif
	.if ecx==1600
		inc edi
		mov		word ptr [edi],' '
		inc edi
		mov		word ptr [edi],' '
		inc edi
		mov		word ptr [edi],' '
		inc edi
		mov		word ptr [edi],' '
		inc edi
		mov		word ptr [edi],' '
		inc edi
		mov		word ptr [edi],' '
		inc edi
		mov		word ptr [edi],' '
		inc edi
		mov		word ptr [edi],' '
		inc edi
		mov		word ptr [edi],' '
		inc edi
		mov		word ptr [edi],' '
	.endif
	inc		edi
	retn

Nybble:
	rol		eax,4
	push	eax
	and		eax,0Fh
	.if eax<=9
		add		eax,'0'
	.else
		add		eax,hex
	.endif
	mov		edx,eax
	pop		eax
	retn

Ascii:
	.if ecx<16
		push	ecx
		sub		ecx,16
		neg		ecx
		mov		eax,ecx
		shl		ecx,1
		add		ecx,eax
		mov		al,' '
		rep stosb
		pop		ecx
	.endif
	sub		ebx,ecx
	push	ecx
	.while ecx
		mov		al,[esi+ebx]
		.if al<20h || al>7Eh
			mov		al,'.'
		.endif
		mov		[edi],al
		inc		edi
		inc		ebx
		dec		ecx
	.endw
	pop		ecx
	sub		ecx,16
	neg		ecx
	mov		al,' '
	rep stosb
	retn

HexLine proc uses ebx esi edi,lpMem:DWORD,nBytesH:DWORD,nLine:DWORD,lpString:DWORD

	mov		esi,lpMem
	mov		edi,lpString
	mov		byte ptr [edi],0
	mov		ebx,nLine
	shl		ebx,4
	.if ebx<=nBytesH
		mov		eax,ebx
		;call	HexAddr
		xor		ecx,ecx
		.while ebx<nBytesH && ecx<16
			call	HexByte
		.endw
		call	Ascii
		xor		eax,eax
		inc		eax
	.else
		xor		eax,eax
	.endif
	ret

HexLine endp
HexAnswer proc uses ebx esi edi,lpMemHA:DWORD,nBytesHA:DWORD
LOCAL i:DWORD
				mov i,0
				mov eax,nBytesHA
				shr eax,4
				mov edi,eax
				.while edi
					mov esi,lpMemHA
					add esi,i	
					invoke HexLine,esi,16,0,addr bufferh
					invoke logstat,addr bufferh
					add i,16
					dec edi
				.endw
				; maradék utolsó sor
				mov esi,lpMemHA
				add esi,i
				mov eax,nBytesHA
				and eax,0FH	
				invoke HexLine,esi,eax,0,addr bufferh
				invoke logstat,addr bufferh
				ret
HexAnswer endp
UpdateDropdown proc uses esi
				invoke SendMessage,hLB1,CB_DELETESTRING,0,0
				invoke SendMessage,hLB2,CB_DELETESTRING,0,0
				mov esi,offset FileFilter
				mov word ptr [esi],'  '
				invoke SendMessage,hLB1,CB_INSERTSTRING,0,esi
				invoke SendMessage,hLB2,CB_INSERTSTRING,0,esi
				invoke SendMessage,hLB1,CB_SETITEMDATA,0,P2kIconIndex
				invoke SendMessage,hLB2,CB_SETITEMDATA,0,P2kIconIndex
				ret
UpdateDropdown endp
end start


