include \RadAsm\masm\inc\radbg.inc  ;debug
;
; Vkim's debug
;
include \radasm\masm\inc\debug.inc
includelib \Radasm\masm\lib\debug.lib

DBGWIN_DEBUG_ON = 1 ;turn it off if you don't want to include debug info into the program
DBGWIN_EXT_INFO = 1 ;turn it off if you don't want to include extra debug info into the program


.code

DevMonitor_Proc proc near
@@init_fail:
                ;push    3E8h
                ;call    Sleep
                call FindUSBClass
                cmp     _DevIF, 0 ;already in p2kmode ?
                jnz      @@alreadyp2k
                
                mov eax,0
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
                cmp     eax, 0
                jnz     @@no_comm
				mov fromThread,0
	            call    Switch_mode
                .if eax==0
	                push    1388h
	                call    Sleep
				.endif	                
				call    SwitchFromDataCard
                call    FindUSBClass
                cmp     _DevIF, 0
                jz      @@init_failexit
@@alreadyp2k:     mov     DevFound, 1
                invoke GetMsgAddr,37
                invoke logstat,eax
                mov P2kStatus,1
                ret
@@init_failexit:
				.if fromThread==0  
					invoke GetMsgAddr,38
	                invoke logstat,eax
					invoke SendMessage,hLog,LB_ADDSTRING,0,eax ;addr txt_noport
					invoke lstrcpy,addr bufferx,StrAddr ("Maybe your option settings is P2k/P2k05 but your phone is Linux based.")
					invoke lstrcat,addr bufferx,addr crlf
					invoke lstrcat,addr bufferx,StrAddr ("If this is the first run, after p2k drivers installed, simply press no.")
					invoke lstrcat,addr bufferx,addr crlf
					invoke lstrcat,addr bufferx,StrAddr ("Do you want to change options to P2k over USBLAN mode, and re-start application ?")
					invoke MessageBox,hWnd,addr bufferx,StrAddr("Warning !!"),MB_ICONQUESTION+MB_YESNOCANCEL
					.if eax==IDYES
						mov isUSBLAN,3
						mov isP2k05,1
						mov ManualP2k05,1
						mov startInfo.dwFlags,STARTF_USESHOWWINDOW
						mov startInfo.wShowWindow,SW_HIDE
						invoke CreateProcess,NULL,StrAddr("restart"),NULL,NULL,FALSE,\ 
	        		      NORMAL_PRIORITY_CLASS,\ 
	              		  NULL,NULL,ADDR startInfo,ADDR processInfo
	              		invoke SendMessage,hWnd,WM_CLOSE,0,0  
					.elseif eax==IDNO
						mov startInfo.dwFlags,STARTF_USESHOWWINDOW
						mov startInfo.wShowWindow,SW_HIDE
						invoke CreateProcess,NULL,StrAddr("restart"),NULL,NULL,FALSE,\ 
	        		      NORMAL_PRIORITY_CLASS,\ 
	              		  NULL,NULL,ADDR startInfo,ADDR processInfo
	              		invoke SendMessage,hWnd,WM_CLOSE,0,0  
					.endif
					mov fromThread,1
				.endif
				mov P2kStatus,0
				ret
@@no_comm:
				call    SwitchFromDataCard
                call    FindUSBClass
                cmp     _DevIF, 0
                jz      @@init_failexit2
				jmp @@alreadyp2k
@@init_failexit2:
				.if fromThread==0  
					invoke GetMsgAddr,38
    	            invoke logstat,eax
					mov fromThread,1
				.endif
				mov P2kStatus,0
				ret
;                push    0
;                push    1
;                push    402h
;                push    Dlg_hwnd
;                call    SendMessageA
;
;                mov     eax, Dev_Name_Ptr
;                add     eax, 4
;                push    eax
;                push    offset str_devclass_key
;                push    offset str_buf
;                call    wsprintfA
;                add     esp, 0Ch
;                mov     byte ptr [str_buf+56h], '#'
;                mov     byte ptr [str_buf+57h], '#'
;                mov     byte ptr [str_buf+59h], '#'
;
;                push    offset Key_Class_handle  ; handle
;                push    20019h         ; access mask
;                push    0              ; res
;                push    offset str_buf ; subkey
;                push    80000002h      ; key
;                call    RegOpenKeyExA
;
;                push    0 ; async flag
;                push    0; Key_Event
;                push    5 ;notify filter - name+last_set
;                push    1 ; flag subkey notify
;                push    Key_Class_handle
;                call    RegNotifyChangeKeyValue
;
;                push    Key_Class_handle
;                call    RegCloseKey
;
;                push    _DevIF
;                call    CloseHandle
;
;                push    Dev_Name_Ptr
;                call    GlobalFree
;
;                mov     DevFound, 0
;                mov     _DevIF, 0
;
;                push    0
;                push    0
;                push    402h
;                push    Dlg_hwnd
;                call    SendMessageA
;
;                push    1388h
;                call    Sleep
;                jmp     @@init_fail
DevMonitor_Proc endp
DevMonitor_ProcLAN proc near
@@init_fail:
                cmp     _DevIF, 0 ;already in usblan mode ?
                jnz      @@alreadylan
                call FindUSBLAN
                mov eax,AlreadyMapped ;LANStatus
                cmp eax,0
                jnz @@alreadylan
                mov eax,0
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
                cmp     eax, 0
                jnz     @@no_commLAN
                .if fromThread<2
                	mov fromThread2,1
	            	call    Switch_modeLAN
	            .endif	
                .if eax==0
	                push    400h
	                call    Sleep
				.endif	                
				
				
                call    FindUSBLAN
                cmp     _DevIF, 1
                jnz      @@init_failexitLAN
@@alreadylan:     mov     DevFound, 1
                ;invoke GetMsgAddr,37
                ;invoke logstat,eax 
               ; mov LANStatus,1
                ret
@@no_commLAN:	.if fromThread==0  
					invoke GetMsgAddr,38
	                invoke logstat,eax
				.endif
				.if fromThread==4 && fromThread2==1
					invoke lstrcpy,addr bufferx,StrAddr ("Maybe your settings is P2k over USBLAN, but your phone is P2k/P2k05.")
					invoke lstrcat,addr bufferx,addr crlf
					invoke lstrcat,addr bufferx,StrAddr ("Do you want to change options to P2k/P2k05 mode, and re-start application ?")
					invoke MessageBox,hWnd,addr bufferx,StrAddr("Warning !!"),MB_ICONQUESTION+MB_YESNO
					.if eax==IDYES
						mov isUSBLAN,0
						mov isP2k05,0
						mov ManualP2k05,0
						mov isFileFilter,0
						mov startInfo.dwFlags,STARTF_USESHOWWINDOW
						mov startInfo.wShowWindow,SW_HIDE
						invoke CreateProcess,NULL,StrAddr("restart"),NULL,NULL,FALSE,\ 
	        		      NORMAL_PRIORITY_CLASS,\ 
	              		  NULL,NULL,ADDR startInfo,ADDR processInfo
	              		invoke SendMessage,hWnd,WM_CLOSE,0,0  
					.endif
				.endif
                inc fromThread
				ret
@@init_failexitLAN:
				mov fromThread,0 
				;	invoke GetMsgAddr,38
	            ;    invoke logstat,StrAddr ("lan error") ;eax
				inc fromThread
				mov LANStatus,0
				ret
DevMonitor_ProcLAN endp

logstat proc logtxt:DWORD
LOCAL lbuf[512]:BYTE

	.if stay_quiet==1 && isVerboseLog==0
		ret
	.endif
	;.if isSplash==0
		invoke SendDlgItemMessage,hWnd,1001,LB_ADDSTRING,0,logtxt			
		invoke SendDlgItemMessage,hWnd,1001,LB_SETCURSEL,eax,0
	;.endif	
	;
	; write to file .log
	;
	invoke lstrcpy,addr lbuf,addr LaunchDir
	invoke lstrcat,addr lbuf,StrAddr("\.log")
	invoke CreateFile,addr lbuf,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	mov hSaveFile,eax
	invoke SetFilePointer,hSaveFile,0,0,FILE_END
	invoke lstrlen,logtxt
	invoke WriteFile,hSaveFile,logtxt,eax,addr writtenb,0
	invoke WriteFile,hSaveFile,addr crlf,2,addr writtenb,0
	invoke CloseHandle,hSaveFile
	ret
logstat endp
logstat2 proc logtxt:DWORD
	.if stay_quiet==1 && isVerboseLog==0
		ret
	.endif
	invoke SendDlgItemMessage,hWnd,1001,LB_GETCURSEL,0,0			
	invoke SendDlgItemMessage,hWnd,1001,LB_DELETESTRING,eax,0			
	invoke SendDlgItemMessage,hWnd,1001,LB_INSERTSTRING,eax,logtxt			
	invoke SendDlgItemMessage,hWnd,1001,LB_SETCURSEL,eax,0
	ret
logstat2 endp
;####################################################
;
;  P2K IO Procedures
;
;####################################################


; Make Filelist of P2K phone

;ListP2K         Proc near
;
;arg_0           = dword ptr  8
;
;                push    ebp
;                mov     ebp, esp
;                pusha
;
;                push    0h
;                push    0h
;                push    1009h           ; Clear ListBox
;                push    3F0h
;                push    [ebp+arg_0]
;                call    SendDlgItemMessageA
;
;                ;push    offset str_Search_req
;                invoke    logstat,offset str_Search_req
;
;; query filelist from phone
;                push    [ebp+arg_0]
;                call    FSAC_search_file
;                cmp     eax, 0
;                jnz     @@fail
;
;                ;push    offset str_ok
;                invoke    logstat,offset str_ok
;
;; Convert flags & size toBig-Endian
;; and add items to ListBox
;
;                mov     edi, Files_found
;                xor     edx, edx
;                mov     esi, SearchBuf_Ptr
;                mov     ebx, FileList_RecSize
;@@loop_1:
;                movzx   eax, word ptr [esi]
;                xchg    ah,al
;                mov     ecx, eax
;                add     esi, 4
;@@loop_2:
;                mov     eax, [esi+ebx-4]
;                xchg    ah, al
;                rol     eax,10h
;                xchg    ah,al
;                mov     [esi+ebx-4], eax
;
;                mov     ax, [esi+ebx-6h]
;                xchg    ah, al
;                mov     [esi+ebx-6], ax
;
;                mov     ax, [esi+ebx-8]
;                xchg    ah, al
;                mov     [esi+ebx-8], ax
;
;                push    esi
;                call    GetFile_ext
;
;                push    0
;                push    eax
;                push    esi
;                mov     eax, [esi+ebx-8]
;                push    eax
;                mov     eax, [esi+ebx-4]
;                push    eax
;                push    [ebp+arg_0]
;                call    AddRow
;
;                add     esi, ebx
;
;                inc     edx
;                dec     edi
;                loop    @@loop_2
;
;                cmp     edi, 0
;                jnz     @@loop_1
;
;; log result
;                ;push    offset str_Files_Added
;                invoke    logstat,offset str_Files_Added
;
;                push    edx
;                push    offset str_dec
;                push    offset str_buf
;                call    wsprintfA
;                add     esp, 0Ch
;
;                ;push    offset str_buf
;                invoke    logstat,offset str_buf
;
;                ;push    offset crlf
;                invoke    logstat,offset crlf
;
;                push   [ebp+arg_0]
;                call   GetVolInfo
;
;@@exit:
;                popa
;                leave
;                retn 4
;@@fail:
;                ;push    offset str_fail
;                invoke    logstat,offset str_fail
;                jmp     @@exit
;ListP2K         endp
;
;GetFile_ext       proc near
;arg_0             = dword ptr  8
;
;                  push    ebp
;                  mov     ebp, esp
;
;                  push    ebx
;                  push    edx
;                  push    esi
;
;                  mov     eax, 0
;                  mov     edx, 0
;                  mov     ebx, FileList_RecSize
;                  sub     ebx, 8
;                  mov     esi, [ebp+arg_0]
;@@char_loop:
;                  cmp     byte ptr [esi+eax], 0
;                  jz      @@extdone
;                  cmp     byte ptr [esi+eax], '.'
;                  jnz     @@next_char
;                  mov     edx, esi
;                  add     edx, eax
;                  inc     edx
;@@next_char:
;                  inc     eax
;                  cmp     eax, ebx
;                  jna     @@char_loop
;@@extdone:
;                  cmp     edx, 0
;                  jnz     @@ok
;                  mov     edx, offset str_null
;@@ok:
;                  mov     eax, edx
;
;                  pop     esi
;                  pop     edx
;                  pop     ebx
;                  leave
;                  retn 4
;GetFile_ext       endp
;
;Get_List_FileSize proc near
;
;arg_0           = dword ptr  8
;
;                  push    ebp
;                  mov     ebp, esp
;
;                  push    edi
;                  push    esi
;                  push    ebx
;                  push    edx
;                  push    ecx
;
;
;                  mov     ebx, [ebp+arg_0]
;                  mov     edi, Files_found
;                  xor     edx, edx
;                  mov     esi, SearchBuf_Ptr
;@@loop_1:
;                  movzx   eax, word ptr [esi]
;                  xchg    ah,al
;                  mov     ecx, eax
;                  add     esi, 4
;@@loop_2:
;                  push    esi
;                  push    ecx
;                  mov     ebx, [ebp+arg_0]
;                  mov     ecx, 0
;@@loop_cmp:
;                  mov     al, [esi]
;                  cmp     al, [ebx+ecx]
;                  jnz     @@next
;                  cmp     al, 0
;                  jz      @@ok
;                  inc     ecx
;                  inc     esi
;                  mov     eax, FileList_RecSize
;                  sub     eax, 8
;                  cmp     ecx, eax
;                  jz      @@ok
;                  jmp     @@loop_cmp
;@@ok:
;                  pop     ecx
;                  pop     esi
;
;                  mov     eax, FileList_RecSize
;                  mov     eax, [esi+eax-4]
;                  jmp     @@exit
;@@next:
;                  pop     ecx
;                  pop     esi
;
;                  add     esi, FileList_RecSize
;
;                  inc     edx
;                  dec     edi
;                  loop    @@loop_2
;
;                  cmp     edi, 0
;                  jnz     @@loop_1
;                  mov     eax,-1
;@@exit:
;                  pop     ecx
;                  pop     edx
;                  pop     ebx
;                  pop     esi
;                  pop     edi
;                  leave
;                  retn 4
;Get_List_FileSize endp
;
;Get_List_FileAttr proc near
;
;arg_0           = dword ptr  8
;
;                  push    ebp
;                  mov     ebp, esp
;
;                  push    edi
;                  push    esi
;                  push    ebx
;                  push    edx
;                  push    ecx
;
;
;                  mov     ebx, [ebp+arg_0]
;                  mov     edi, Files_found
;                  xor     edx, edx
;                  mov     esi, SearchBuf_Ptr
;@@loop_1:
;                  movzx   eax, word ptr [esi]
;                  xchg    ah,al
;                  mov     ecx, eax
;                  add     esi, 4
;@@loop_2:
;                  push    esi
;                  push    ecx
;                  mov     ebx, [ebp+arg_0]
;                  mov     ecx, 0
;@@loop_cmp:
;                  mov     al, [esi]
;                  cmp     al, [ebx+ecx]
;                  jnz     @@next
;                  cmp     al, 0
;                  jz      @@ok
;                  inc     ecx
;                  inc     esi
;                  mov     eax, FileList_RecSize
;                  sub     eax, 8
;                  cmp     ecx, eax
;                  jz      @@ok
;                  jmp     @@loop_cmp
;@@ok:
;                  pop     ecx
;                  pop     esi
;
;                  mov     eax, FileList_RecSize
;                  mov     eax, [esi+eax-8]
;                  jmp     @@exit
;@@next:
;                  pop     ecx
;                  pop     esi
;
;                  add     esi, FileList_RecSize
;
;                  inc     edx
;                  dec     edi
;                  loop    @@loop_2
;
;                  cmp     edi, 0
;                  jnz     @@loop_1
;                  mov     eax,-1
;@@exit:
;                  pop     ecx
;                  pop     edx
;                  pop     ebx
;                  pop     esi
;                  pop     edi
;                  leave
;                  retn 4
;Get_List_FileAttr endp
;
;RingTonesUpdate   proc near
;                  push    ecx
;                  push    esi
;                  push    edi
;
;                  push    offset seem_buf
;                  push    0
;                  push    0
;                  push    1
;                  push    4Ch
;                  call    Cmd_RDELEM
;
;                  push    offset str_profiles_readed
;                  call    logstat
;                  push    1F4h
;                  call    Sleep
;
;                  dec     seem_read_bytes
;                  mov     esi, offset seem_buf
;                  inc     esi
;                  mov     edi, offset seem_data
;                  mov     ecx, seem_read_bytes
;                  rep     movsb
;
;                  mov     edi, offset seem_data
;                  mov     byte ptr [edi+01h], 2
;                  mov     byte ptr [edi+02h], 2
;                  mov     byte ptr [edi+0Ch], 2
;                  mov     byte ptr [edi+0Dh], 2
;                  mov     byte ptr [edi+17h], 2
;                  mov     byte ptr [edi+18h], 2
;                  mov     byte ptr [edi+22h], 2
;                  mov     byte ptr [edi+23h], 2
;                  mov     byte ptr [edi+2Dh], 2
;                  mov     byte ptr [edi+2Eh], 2
;
;                  push    seem_read_bytes
;                  push    0
;                  push    1
;                  push    4Ch
;                  call    Cmd_STELEM
;
;                  push    1F4h
;                  call    Sleep
;
;                  push    offset str_profiles_updated
;                  call    logstat
;
;                  push    offset fn_mytonedb
;                  call    FSAC_delete
;
;                  push    offset str_tonebase_deleted
;                  call    logstat
;                  push    1F4h
;                  call    Sleep
;
;                  call   P2K_Restart
;
;                  pop     edi
;                  pop     esi
;                  pop     ecx
;                  retn
;RingTonesUpdate   endp
;
;;--------------------------------------
;; Write file to Phone
;
;Upload          proc    near
;
;arg_0           = dword ptr  8
;
;                push    ebp
;                mov     ebp,esp
;                pusha
;
;                push    offset str_upload
;                call    logstat
;
;                push    offset str_buf
;                call    FSAC_GetVolName
;                cmp     eax, 0
;                jz      @@volinfo_ok
;                push    offset str_volinfofail
;                call    logstat
;                jmp     @@exit
;
;@@volinfo_ok:
;                push    offset str_buf
;                call    FSAC_volume_space
;                cmp     eax, 0
;                jz      @@volinfo_2_ok
;                push    offset str_volinfofail
;                call    logstat
;                jmp     @@exit
;@@volinfo_2_ok:
;                mov     edi, offset fname_buf
;                mov     eax, 0
;                mov     ecx, 80h
;                rep     stosd
;
;                mov     fname_buf, 0
;                mov     fname_t_buf, 0
;                mov     OFN_Flags, 80200h
;                push    offset OpenFileNameSize
;                call    GetOpenFileNameA
;                cmp     eax, 0
;                jz      @@exit
;
;                mov     esi, offset fname_buf
;
;                push    offset fname_buf
;                call    lstrlenA
;                inc     eax
;                cmp     byte ptr [eax+esi], 0
;                jz      @@single_file
;@@next_ul:
;                add     esi, eax
;@@single_file:
;                push    -1
;                push    0
;                push    3 ; open existing
;                push    0
;                push    0
;                push    0C0000000h ; generic RW
;                push    esi
;                call    CreateFileA
;                mov     FHandle, eax
;                cmp     eax,-1
;                jnz     @@_open_ok
;                push    offset str_openfail
;                call    logstat
;                jmp     @@exit
;@@_open_ok:
;                push    eax
;
;                push    80h
;                push    offset str_buf
;                push    1017
;                push    [ebp+arg_0]
;                call    GetDlgItemTextA
;
;                cmp     byte ptr [fname_t_buf], 0
;                mov     eax, offset fname_t_buf
;                jnz     @@single_file_t
;                mov     eax, esi
;@@single_file_t:
;                push    eax
;                push    offset str_buf
;                call    lstrcatA
;
;                push    offset str_buf ; fname_t_buf
;                call    logstat
;
;                pop     eax
;
;                push    offset filesize_ex
;                push    eax
;                call    GetFileSize
;
;                cmp     filesize_ex, 0
;                jnz     @@fail_size
;                cmp     eax, 0
;                jz      @@fail_size
;                cmp     eax, VolSpace
;                jb      @@_size_ok
;@@fail_size:
;                push    offset str_sizefail
;                call    logstat
;                jmp     @@try_next_ul
;
;@@_size_ok:
;                sub     VolSpace, eax
;                mov     FileSize, eax
;                push    eax
;                push    40h
;                call    GlobalAlloc
;                cmp     eax, 0
;                jz      @@exit_fclose
;                mov     FileBuf_Ptr, eax
;
;                push    0 ; overlapped
;                push    offset file_readed ; bytes readen
;                push    FileSize  ; bytes to read
;                push    FileBuf_Ptr
;                push    FHandle
;                call    ReadFile
;                cmp     eax, 0
;                jz      @@exit_fclose
;                mov     eax, FileSize
;                cmp     file_readed, eax
;                jnz     @@exit_fclose
;                push    FHandle
;                call    CloseHandle
;
;; Begin write
;                push    offset str_buf ; fname_t_buf
;                call    lstrlenA
;                mov     ecx, FileList_RecSize
;                cmp     ecx, 0
;                jz      @@warn_no_fl
;                sub     ecx, 8
;                cmp     eax, ecx
;                ja      @@exit_fclose
;@@warn_no_fl:
;                push    0 ; attrib
;                push    offset str_buf ; fname_t_buf             ; fname_ptr
;                call    FSAC_open
;                test    eax, eax
;                jnz     short @@exit
;
;                push    FileSize
;                push    FileBuf_Ptr
;                call    FSAC_write
;                test    eax, eax
;                jnz     short @@close ; fail
;@@close:
;                call    FSAC_close
;;                test    eax, eax
;;                jnz      @@exit   ; fail
;                push    offset str_ok
;                call    logstat
;@@try_next_ul:
;                push    esi
;                call    lstrlenA
;                inc     eax
;                cmp     byte ptr [esi+eax], 0
;                jnz     @@next_ul
;@@upl_done:
;                cmp     AutoUpd, 1
;                jnz     @@skip_upd
;                push    [ebp+arg_0]
;                call    ListP2K
;@@skip_upd:
;
;@@exit_fclose:
;                push    FHandle
;                call    CloseHandle
;
;@@exit:
;                popa
;                leave
;                retn 4
;Upload          endp
;
;ChangeAttrib    proc near
;arg_0           = dword ptr  8
;
;                push    ebp
;                mov     ebp, esp
;                pusha
;
;                mov     next_sel_item, -1
;@@next:                              ; Find selected item
;                                        ; Find selected item
;                push    2               ; flags - search for selected item
;                push    next_sel_item   ; start from beginning
;                push    100Ch           ; LVM_GETNEXTITEM
;                push    3F0h
;                push    [ebp+arg_0]
;                call    SendDlgItemMessageA
;                cmp     eax, -1
;                je      @@no_more_sel
;                mov     next_sel_item, eax
;
;                push    offset str_attr
;                call    logstat
;
;                mov     lv_Item, 0
;                mov     lv_SubItem, 0
;                mov     lv_Text, offset lv_get_text
;                mov     lv_TextMax, 105h
;
;                push    offset lv_Mask
;                push    eax
;                push    102Dh           ; LVM_GETITEMTEXT
;                push    3F0h
;                push    [ebp+arg_0]
;                call    SendDlgItemMessageA
;
;                push    offset lv_get_text
;                call    logstat
;
;                push    0
;                push    0
;                push    1015
;                push    [ebp+arg_0]
;                call    GetDlgItemInt
;                cmp     eax, 10000h
;                jna     @@ok
;                mov     eax, 0
;@@ok:
;                push    eax
;                push    offset lv_get_text
;                call    FSAC_open
;                test    eax, eax
;                jnz     @@openfail
;
;                push    offset str_ok
;                call    logstat
;
;                call    FSAC_close
;@@openfail:
;                jmp     @@next
;@@no_more_sel:
;                cmp     next_sel_item, -1
;                jnz     @@exit
;                push    offset str_no_files_sel
;                call    logstat
;@@exit:
;                cmp     AutoUpd, 1
;                jnz     @@skip_upd
;                push    [ebp+arg_0]
;                call    ListP2K
;@@skip_upd:
;
;                popa
;                leave
;                retn    4
;ChangeAttrib    endp
;
;Download        proc
;
;arg_0           = dword ptr  8
;
;                push    ebp
;                mov     ebp, esp
;                pusha
;
;                mov     files_dl_first, 0
;                mov     next_sel_item, -1
;@@dl_next:                              ; Find selected item
;
;                push    2               ; flags - search for selected item
;                push    next_sel_item   ; start from beginning
;                push    100Ch           ; LVM_GETNEXTITEM
;                push    3F0h
;                push    [ebp+arg_0]
;                call    SendDlgItemMessageA
;                cmp     eax, -1
;                je      @@no_more_sel
;                mov     next_sel_item, eax
;
;                push    offset str_download
;                call    logstat
;
;                mov     lv_Item, 0
;                mov     lv_SubItem, 0
;                mov     lv_Text, offset lv_get_text
;                mov     lv_TextMax, 105h
;
;                push    offset lv_Mask
;                push    eax
;                push    102Dh           ; LVM_GETITEMTEXT
;                push    3F0h
;                push    [ebp+arg_0]
;                call    SendDlgItemMessageA
;
;                push    offset lv_get_text
;                call    logstat
;
;                push    offset lv_get_text
;                call    Get_List_FileSize
;
;                cmp     eax, -1
;                jz      @@sizefail
;                cmp     eax, 0
;                jnz     @@size_ok
;@@sizefail:
;                push    offset str_sizefail
;                call    logstat
;                push    Download_BufPtr
;                call    GlobalFree
;                jmp     @@exit
;
;@@size_ok:
;                mov     Download_FSize, eax
;
;                push    eax
;                push    40h
;                call    GlobalAlloc
;                cmp     eax, 0
;                jnz     @@mem_ok
;                push    offset str_memfail
;                call    logstat
;                jmp     @@exit
;
;@@mem_ok:
;                mov     Download_BufPtr, eax
;
;                push    offset lv_get_text
;                call    Get_List_FileAttr
;                mov     stay_quiet, 1
;                push    eax
;                push    offset lv_get_text
;                call    FSAC_open
;                test    eax, eax
;                jz      @@open_ok
;                mov     stay_quiet, 0
;                push    offset lv_get_text
;                call    Get_List_FileAttr
;                push    eax
;                push    offset lv_get_text
;                call    FSAC_open
;                test    eax, eax
;                jz      @@open_ok
;                push    offset str_openfail
;                call    logstat
;                push    Download_BufPtr
;                call    GlobalFree
;                mov     eax, -1
;                jmp     @@exit
;
;@@open_ok:
;                mov     stay_quiet, 0
;                push    0
;                push    0
;                call    FSAC_seek
;                test    eax, eax
;                jz      @@seek_ok
;                push    offset str_seekfail
;                call    logstat
;                call    FSAC_close
;                push    Download_BufPtr
;                call    GlobalFree
;                mov     eax, -1
;                jmp     @@exit
;
;@@seek_ok:
;                push    Download_FSize
;                push    Download_BufPtr
;                call    FSAC_read
;                cmp     eax, 0
;                jz      @@read_ok
;                push    offset str_readfail
;                call    logstat
;                call    FSAC_close
;                push    Download_BufPtr
;                call    GlobalFree
;                mov     eax, -1
;                jmp     @@exit
;@@read_ok:
;
;                call    FSAC_close
;;                cmp     eax, 0
;;                jz      @@close
;
;                push    10Dh
;                push    offset fname_buf
;                push    offset lv_get_text
;                call    GetFileTitleA
;
;                cmp     files_dl_first, 0
;                jnz     @@skip_path
;                mov     fname_t_buf, 0
;                push    offset OpenFileNameSize
;                mov     OFN_Flags, 0
;                call    GetSaveFileNameA
;                cmp     eax, 0
;                jnz     @@path_ok
;                push    offset str_canceled
;                call    logstat
;                push    Download_BufPtr
;                call    GlobalFree
;                jmp     @@exit
;
;@@path_ok:
;                mov     files_dl_first, 1
;@@skip_path:
;                push    -1
;                push    0
;                push    1 ; Create new
;                push    0
;                push    0
;                push    0C0000000h ; generic RW
;                push    offset fname_buf
;                call    CreateFileA
;                mov     FHandle, eax
;                cmp     eax,0
;                jnz     @@create_ok
;                push    offset str_fcreatefail
;                call    logstat
;                push    Download_BufPtr
;                call    GlobalFree
;
;@@create_ok:
;                push    0
;                push    offset file_readed
;                push    Download_FSize
;                push    Download_BufPtr
;                push    FHandle
;                call    WriteFile
;                cmp     eax, 0
;                jnz     @@write_ok
;                push    offset str_writefile_fail
;                call    logstat
;                push    FHandle
;                call    CloseHandle
;                call    FSAC_close
;                push    Download_BufPtr
;                call    GlobalFree
;                jmp     @@exit
;
;@@write_ok:
;                push    FHandle
;                call    CloseHandle
;
;                push    Download_BufPtr
;                call    GlobalFree
;
;                push    offset str_ok
;                call    logstat
;                jmp     @@dl_next
;@@no_more_sel:
;                cmp     next_sel_item, -1
;                jnz     @@exit
;                push    offset str_no_files_sel
;                call    logstat
;@@exit:
;                popa
;                leave
;                retn    4
;Download        endp
;
;
;Delete          Proc near
;
;arg_0           = dword ptr  8
;
;                push    ebp
;                mov     ebp, esp
;                pusha
;
;                mov     next_sel_item, -1
;@@next:                              ; Find selected item
;                                        ; Find selected item
;                push    2               ; flags - search for selected item
;                push    next_sel_item   ; start from beginning
;                push    100Ch           ; LVM_GETNEXTITEM
;                push    3F0h
;                push    [ebp+arg_0]
;                call    SendDlgItemMessageA
;                cmp     eax, -1
;                je      @@no_more_sel
;                mov     next_sel_item, eax
;
;                push    offset str_deleting
;                call    logstat
;
;                mov     lv_Item, 0
;                mov     lv_SubItem, 0
;                mov     lv_Text, offset lv_get_text
;                mov     lv_TextMax, 105h
;
;                push    offset lv_Mask
;                push    eax
;                push    102Dh           ; LVM_GETITEMTEXT
;                push    3F0h
;                push    [ebp+arg_0]
;                call    SendDlgItemMessageA
;
;                push    offset lv_get_text
;                call    logstat
;
;                push    offset lv_get_text
;                push    offset str_delete
;                push    offset str_buf
;                call    wsprintfA
;                add     esp, 0Ch
;
;                push    4
;                push    0
;                push    offset str_buf
;                push    [ebp+arg_0]
;                call    MessageBoxA
;                cmp     eax,6
;                jnz     @@cancle
;
;                push    offset lv_get_text
;                call    FSAC_delete
;                cmp     eax, 0
;                jnz     @@fail
;                push    offset str_ok
;                call    logstat
;                jmp     @@next
;@@no_more_sel:
;                cmp     next_sel_item, -1
;                jnz     @@exit_ok
;                push    offset str_no_files_sel
;                call    logstat
;@@exit_ok:
;
;                cmp     AutoUpd, 1
;                jnz     @@skip_upd
;                push    [ebp+arg_0]
;                call    ListP2K
;@@skip_upd:
;@@exit:
;                popa
;                leave
;                retn    4
;@@cancle:
;                push    offset str_canceled
;                call    logstat
;                jmp     @@exit
;@@fail:
;                push    offset str_fail
;                call    logstat



























;                jmp     @@exit
;
;Delete          endp
;
LEUnicode_cvt   proc near

arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    esi
                push    edi
                mov     esi, [ebp+arg_0]
                mov     edi, esi
@@loop:
                lodsw
                ;lodsw
                ;xchg    al, ah
                cmp     ax, 0FFFFh
                jz      @@done
                cmp     ax, 0FF00h
                jz      @@done
                cmp     ax, 00FFh
                jz      @@done
                cmp     ax, 0
                jz      @@done
                stosb ;w
                jmp     @@loop
@@done:
                xor     eax, eax
                stosb ;w
                pop     edi
                pop     esi
                leave
                retn 4
LEUnicode_cvt   endp
GetVolInfo      Proc near uses esi edi ebx

;arg_0           = dword ptr  8

;                push    ebp
;                mov     ebp, esp

                ;pusha
				;**************************
				; Branch here P2kOverUsblan
				;**************************
				cmp isUSBLAN,3
				jnz @@old
				jmp GetVolInfoOU
                ;
                ; p2k05 autoselect
                ;
@@old:          invoke CheckP2k05
   				;
				; some log
				;
				.if isP2k05==1
					invoke GetMsgAddr,103
					invoke logstat,eax
				.else
					.if is3g==0
						invoke GetMsgAddr,100
						invoke logstat,eax
					.elseif is3g==1
						invoke GetMsgAddr,102
						invoke logstat,eax
					.elseif is3g==3
						invoke GetMsgAddr,101
						invoke logstat,eax
					.endif
				.endif	
				invoke GetMsgAddr,16
                invoke lstrcpy,addr bufferx,eax ;addr str_FSAC_Info
                ;invoke  logstat,offset str_FSAC_Info
				.if isCDMA==0
			        push    offset phone_model
	                push    0
	                push    0
	                push    1
	                push    117h
	                invoke Cmd_RDELEM
	                mov esi,offset phone_model
	                ;DbgDump offset phone_model,16
	                push    offset phone_model+2
	                call LEUnicode_cvt
	                invoke lstrcpy,addr bufferx,StrAddr ("GSM Model: ")
	                invoke lstrcat,addr bufferx,addr phone_model+2
	            .else
			        push    offset phone_model
	                push    10
	                push    0
	                push    1
	                push    2827h
	                invoke Cmd_RDELEM
	                mov esi,offset phone_model
	                ;DbgDump offset phone_model,16
	                push    offset phone_model+1
	                call LEUnicode_cvt
	                invoke lstrcpy,addr bufferx,StrAddr ("CDMA Model: ")
	                invoke lstrcat,addr bufferx,addr phone_model+1
	            .endif    
				;invoke GetMsgAddr,77
                ;invoke lstrcpy,addr bufferx,eax ;addr szType
;                .if isCDMA==1
;                	invoke lstrcat,addr bufferx,StrAddr("CDMA phone")
;                .endif
				invoke logstat,addr bufferx ;invoke SetStatusText, 3, 0, ADDR bufferx
				;push offset Partition
				;invoke FSAC_search_file
				.if isCDMA==1
					mov esi,offset FileFilter
					mov byte ptr [esi],"/"
					mov byte ptr [esi+1],"a"
    	            mov eax,-1
	                jmp     @@exit
				.endif
				push offset FileFilter
				call File_Count ;Ex
				invoke dwtoa,Files_found,addr buffery
				invoke GetMsgAddr,79
   	            invoke lstrcpy,addr bufferx,eax ;addr szFiles
       	        invoke lstrcat,addr bufferx,addr buffery
				;invoke logstat,addr bufferx ;invoke SetStatusText, 2, 0, ADDR bufferx

				mov isFileFilter,0

                push    offset volname
                call    FSAC_GetVolName
                test    eax, eax
                jz      @@name_ok
                invoke GetMsgAddr,17
                invoke    logstat,eax ;offset str_volname_fail
                mov eax,-1
                jmp     @@exit
@@name_ok:
                push    esi
                push    edi
                mov     esi,offset volname
                mov     edi,offset str_buf
@@loop:
                lodsw
                xchg    al, ah
                .if al>0f0h
                	mov al," "
                .endif
                stosb
                cmp     al, 0
                jnz     @@loop
                pop     edi
                pop     esi
                invoke GetMsgAddr,20
                invoke lstrcat,addr bufferx,eax ;addr str_volname
                invoke lstrcat,addr bufferx,addr str_buf
                ;invoke logstat,offset bufferx
				invoke GetMsgAddr,78
                invoke lstrcpy,addr bufferx,eax ;addr szName
                invoke lstrcat,addr bufferx,addr str_buf
				;invoke logstat,addr bufferx ;invoke SetStatusText, 1, 0, ADDR bufferx		
				;
				; partitions.....text in srt_buf ( /a /b /c )
				;
                ; actualize CB1,CB2
				;                
					mov CBIndex,5
					.while CBIndex!=0
						invoke SendMessage,hLB1,CB_DELETESTRING,0,0
						invoke SendMessage,hLB2,CB_DELETESTRING,0,0
						dec CBIndex
					.endw		
				;invoke SendMessage,hLB1,CB_RESETCONTENT,0,0
				;invoke SendMessage,hLB2,CB_RESETCONTENT,0,0
				;invoke GetDrives1
				;invoke GetDrives2
				;mov isSlashB,0
				;mov isSlashC,0
				;mov isSlashE,0
				;mov isSlashG,0
				mov CBIndex,0
				invoke GetMsgAddr,116
				invoke SendMessage,hLB1,CB_INSERTSTRING,CBIndex,eax ;addr P2kPattern ; add p2k drive /a
				invoke SendMessage,hLB1,CB_SETITEMDATA,CBIndex,P2kIconIndex
				invoke GetMsgAddr,116
				invoke SendMessage,hLB2,CB_INSERTSTRING,CBIndex,eax ;addr P2kPattern ; add p2k drive /a
				invoke SendMessage,hLB2,CB_SETITEMDATA,CBIndex,P2kIconIndex
				inc CBIndex
				invoke lstrcat,addr str_buf,StrAddr(" ")
				invoke InString,1,addr str_buf,addr szSlashB
				.if eax!=0 ; present
					; set 4th slot if override
					.if CBIndex==3 && isOverrideSlot4==1
						invoke GetMsgAddr,122
						mov esi,offset ManualSlot4
						mov word ptr bx,[esi]
						mov word ptr [eax],bx
						invoke SendMessage,hLB1,CB_INSERTSTRING,CBIndex,eax ;addr P2kPattern ; add p2k drive /empty slot
						invoke GetMsgAddr,122
						invoke SendMessage,hLB2,CB_INSERTSTRING,CBIndex,eax ;addr P2kPattern ; add p2k drive /empty slot
						invoke SendMessage,hLB1,CB_SETITEMDATA,CBIndex,P2kIconIndex
						invoke SendMessage,hLB2,CB_SETITEMDATA,CBIndex,P2kIconIndex
					.else
						invoke GetMsgAddr,117
						invoke SendMessage,hLB1,CB_INSERTSTRING,CBIndex,eax ;addr P2kPattern ; add p2k drive /b
						invoke GetMsgAddr,117
						invoke SendMessage,hLB2,CB_INSERTSTRING,CBIndex,eax ;addr P2kPattern ; add p2k drive /b
						invoke SendMessage,hLB1,CB_SETITEMDATA,CBIndex,P2kIconIndex
						invoke SendMessage,hLB2,CB_SETITEMDATA,CBIndex,P2kIconIndex
					.endif	
					inc CBIndex
					;mov isSlashB,1
				.endif
				invoke InString,1,addr str_buf,addr szSlashC
				.if eax!=0 ; present
					; set 4th slot if override
					.if CBIndex==3 && isOverrideSlot4==1
						invoke GetMsgAddr,122
						mov esi,offset ManualSlot4
						mov word ptr bx,[esi]
						mov word ptr [eax],bx
						invoke SendMessage,hLB1,CB_INSERTSTRING,CBIndex,eax ;addr P2kPattern ; add p2k drive /empty slot
						invoke GetMsgAddr,122
						invoke SendMessage,hLB2,CB_INSERTSTRING,CBIndex,eax ;addr P2kPattern ; add p2k drive /empty slot
						invoke SendMessage,hLB1,CB_SETITEMDATA,CBIndex,P2kIconIndex
						invoke SendMessage,hLB2,CB_SETITEMDATA,CBIndex,P2kIconIndex
					.else
						invoke GetMsgAddr,118
						invoke SendMessage,hLB1,CB_INSERTSTRING,CBIndex,eax ;addr P2kPattern ; add p2k drive /c
						invoke GetMsgAddr,118
						invoke SendMessage,hLB2,CB_INSERTSTRING,CBIndex,eax ;addr P2kPattern ; add p2k drive /c
						invoke SendMessage,hLB1,CB_SETITEMDATA,CBIndex,P2kIconIndex
						invoke SendMessage,hLB2,CB_SETITEMDATA,CBIndex,P2kIconIndex
					.endif
					inc CBIndex
					;mov isSlashC,1
				.endif
				invoke InString,1,addr str_buf,addr szSlashE
				.if eax!=0 ; present
					; set 4th slot if override
					.if CBIndex==3 && isOverrideSlot4==1
						invoke GetMsgAddr,122
						mov esi,offset ManualSlot4
						mov word ptr bx,[esi]
						mov word ptr [eax],bx
						invoke SendMessage,hLB1,CB_INSERTSTRING,CBIndex,eax ;addr P2kPattern ; add p2k drive /empty slot
						invoke GetMsgAddr,122
						invoke SendMessage,hLB2,CB_INSERTSTRING,CBIndex,eax ;addr P2kPattern ; add p2k drive /empty slot
						invoke SendMessage,hLB1,CB_SETITEMDATA,CBIndex,P2kIconIndex
						invoke SendMessage,hLB2,CB_SETITEMDATA,CBIndex,P2kIconIndex
					.else
						invoke GetMsgAddr,119
						invoke SendMessage,hLB1,CB_INSERTSTRING,CBIndex,eax ;addr P2kPattern ; add p2k drive /e
						invoke GetMsgAddr,119
						invoke SendMessage,hLB2,CB_INSERTSTRING,CBIndex,eax ;addr P2kPattern ; add p2k drive /e
						invoke SendMessage,hLB1,CB_SETITEMDATA,CBIndex,P2kIconIndex
						invoke SendMessage,hLB2,CB_SETITEMDATA,CBIndex,P2kIconIndex
					.endif	
					inc CBIndex
					;mov isSlashE,1
				.endif
				invoke InString,1,addr str_buf,addr szSlashG
				.if eax!=0 ; present
					; set 4th slot if override
					.if CBIndex==3 && isOverrideSlot4==1
						invoke GetMsgAddr,122
						mov esi,offset ManualSlot4
						mov word ptr bx,[esi]
						mov word ptr [eax],bx
						invoke SendMessage,hLB1,CB_INSERTSTRING,CBIndex,eax ;addr P2kPattern ; add p2k drive /empty slot
						invoke GetMsgAddr,122
						invoke SendMessage,hLB2,CB_INSERTSTRING,CBIndex,eax ;addr P2kPattern ; add p2k drive /empty slot
						invoke SendMessage,hLB1,CB_SETITEMDATA,CBIndex,P2kIconIndex
						invoke SendMessage,hLB2,CB_SETITEMDATA,CBIndex,P2kIconIndex
					.else
						invoke GetMsgAddr,120
						invoke SendMessage,hLB1,CB_INSERTSTRING,CBIndex,eax ;addr P2kPattern ; add p2k drive /g
						invoke GetMsgAddr,120
						invoke SendMessage,hLB2,CB_INSERTSTRING,CBIndex,eax ;addr P2kPattern ; add p2k drive /g
						invoke SendMessage,hLB1,CB_SETITEMDATA,CBIndex,P2kIconIndex
						invoke SendMessage,hLB2,CB_SETITEMDATA,CBIndex,P2kIconIndex
					.endif	
					inc CBIndex
					;mov isSlashG,1
				.endif
				; remainders are empty slot
				.while CBIndex<4
					; set 4th slot if override
					.if CBIndex==3 && isOverrideSlot4==1
						invoke GetMsgAddr,122
						mov esi,offset ManualSlot4
						mov word ptr bx,[esi]
						mov word ptr [eax],bx
						invoke SendMessage,hLB1,CB_INSERTSTRING,CBIndex,eax ;addr P2kPattern ; add p2k drive /empty slot
						invoke GetMsgAddr,122
						invoke SendMessage,hLB2,CB_INSERTSTRING,CBIndex,eax ;addr P2kPattern ; add p2k drive /empty slot
						invoke SendMessage,hLB1,CB_SETITEMDATA,CBIndex,P2kIconIndex
						invoke SendMessage,hLB2,CB_SETITEMDATA,CBIndex,P2kIconIndex
					.else
						invoke GetMsgAddr,121
						invoke SendMessage,hLB1,CB_INSERTSTRING,CBIndex,eax ;addr P2kPattern ; add p2k drive /empty slot
						invoke GetMsgAddr,121
						invoke SendMessage,hLB2,CB_INSERTSTRING,CBIndex,eax ;addr P2kPattern ; add p2k drive /empty slot
						invoke SendMessage,hLB1,CB_SETITEMDATA,CBIndex,P2kDIconIndex
						invoke SendMessage,hLB2,CB_SETITEMDATA,CBIndex,P2kDIconIndex
					.endif	
					inc CBIndex
				.endw
				;seem slot
					invoke GetMsgAddr,115
					invoke SendMessage,hLB1,CB_INSERTSTRING,CBIndex,eax ;addr P2kPattern ; add p2k drive /empty slot
					invoke GetMsgAddr,115
					invoke SendMessage,hLB2,CB_INSERTSTRING,CBIndex,eax ;addr P2kPattern ; add p2k drive /empty slot
					invoke SendMessage,hLB1,CB_SETITEMDATA,CBIndex,P2kIconIndex
					invoke SendMessage,hLB2,CB_SETITEMDATA,CBIndex,P2kIconIndex
					;mov isCBpopulated,1
;				invoke InString,1,addr str_buf,addr szSlashC
;				.if eax!=0 ; present
;					invoke SendMessage,hLB1,CB_SETITEMDATA,2,P2kIconIndex
;					invoke SendMessage,hLB2,CB_SETITEMDATA,2,P2kIconIndex
;				.else ; not present
;					invoke SendMessage,hLB1,CB_SETITEMDATA,2,P2kDIconIndex
;					invoke SendMessage,hLB2,CB_SETITEMDATA,2,P2kDIconIndex
;				.endif
;				invoke InString,1,addr str_buf,addr szSlashE
;				.if eax!=0 ; present
;					invoke SendMessage,hLB1,CB_SETITEMDATA,3,P2kIconIndex
;					invoke SendMessage,hLB2,CB_SETITEMDATA,3,P2kIconIndex
;				.else ; not present
;					invoke SendMessage,hLB2,CB_SETITEMDATA,3,P2kDIconIndex
;					invoke SendMessage,hLB1,CB_SETITEMDATA,3,P2kDIconIndex
;				.endif
;				invoke InString,1,addr str_buf,addr szSlashA
;				.if eax!=0 && isSlashA==1
;					mov Partition,"a"
;				.endif
;				invoke InString,1,addr str_buf,addr szSlashB
;				.if eax!=0 && isSlashB==1
;					mov Partition,"b"
;				.endif
;				invoke InString,1,addr str_buf,addr szSlashC
;				.if eax!=0 && isSlashC==1
;					mov Partition,"c"
;				.endif
;				invoke InString,1,addr str_buf,addr szSlashE
;				.if eax!=0 && isSlashE==1
;					mov Partition,"e"
;				.endif
;				invoke InString,1,addr str_buf,addr szSlashG
;				.if eax!=0 && isSlashE==1
;					mov Partition,"g"
;				.endif
				;
				; get selected volume
				;
				invoke SendDlgItemMessage,hWnd,1005,CB_GETLBTEXT,P2kVolume,addr bufferx
				invoke logstat,addr bufferx
				mov esi,offset bufferx
				mov al,byte ptr [esi+1]
				.if byte ptr [esi]!="/"
					mov al,"a"
				.endif
				mov Partition,al
				;
				; update filter string
				;
				mov esi,offset FileFilter
				mov al,Partition
				mov [esi+1],al
                push    offset SlashPartition ;volname
                call File_GetFreeSpace
                ;call    FSAC_volume_space
                ;test    eax, eax
                ;jz      @@size_ok
                cmp eax,-1
                jnz      @@size_ok
                invoke GetMsgAddr,19
                push    eax ;offset str_volsize_fail
                call    logstat
                mov eax,-1
                jmp     @@exit
@@size_ok:
                ;push    offset str_volsize
				mov VolSpace,eax
				
				invoke GetMsgAddr,99
				invoke lstrcpy,addr bufferx,eax
				invoke lstrcat,addr bufferx,addr FileFilter
				invoke logstat,addr bufferx

                ;call    logstat
                invoke GetMsgAddr,21
                invoke lstrcpy,addr bufferx,eax ;addr str_volsize

                mov     eax, VolSpace
                xor     edx, edx
                mov     ecx, 400h
                div     ecx

                push    eax
                push    offset str_dec
                push    offset str_buf
                call    wsprintfA
                add     esp, 0Ch

                ;push    offset str_buf
                ;call    logstat
                invoke lstrcat,addr bufferx,addr str_buf 

                ;push    offset str_kb
                ;call    logstat
                invoke GetMsgAddr,22
                invoke lstrcat,addr bufferx,eax ;addr str_kb
                invoke logstat,addr bufferx 

				invoke GetMsgAddr,80
                invoke lstrcpy,addr bufferx,eax ;addr szFree
                invoke lstrcat,addr bufferx,addr str_buf
                invoke lstrcat,addr bufferx,addr szKb
				;invoke logstat,addr bufferx ;invoke SetStatusText, 0, 0, ADDR bufferx		
						

		
;				invoke lstrcpy,addr bufferx,StrAddr("FirmWare: ")
;				invoke P2K_ReadFW
;				mov esi,offset Cmd_Recv_Buf
;				push esi
;				mov eax,[Cmd_Recv_Size]
;				add esi,eax
;				mov byte ptr [esi],0
;				pop esi
;				add esi,5
;				invoke lstrcat,addr bufferx,esi
;				invoke logstat,addr bufferx
		;		invoke P2K_Vibrate
		
				mov eax,0 ;all ok
@@exit:
                ;leave
                ret    ;4
            	;
            	; new getVolInfo for USBLAN devices, only number of files now
            	;    
GetVolInfoOU:
				mov esi,offset FileFilter
				inc esi
				push esi
				call File_Count ;Ex
				;call File_CountOld
				dec eax
				dec eax
				mov Files_found,eax
				; volume
				invoke GetMsgAddr,78
                invoke lstrcpy,addr bufferx,eax ;addr szName
                invoke lstrcat,addr bufferx,StrAddr ("/")
				invoke logstat,addr bufferx ;				invoke SetStatusText, 1, 0, ADDR bufferx		
;				; files
;				invoke dwtoa,Files_found,addr buffery
;				invoke GetMsgAddr,79
;   	            invoke lstrcpy,addr bufferx,eax ;addr szFiles
;       	        invoke lstrcat,addr bufferx,addr buffery
;				invoke SetStatusText, 2, 0, ADDR bufferx
				; model
				invoke ezxname
				invoke GetMsgAddr,77
                invoke lstrcpy,addr bufferx,eax 
                invoke lstrcat,addr bufferx,addr EzxModel
				invoke logstat,addr bufferx ;				invoke SetStatusText, 3, 0, ADDR bufferx
				; restore progressbar to zero
				invoke SendMessage,hBar,PBM_SETPOS,0,0
;				invoke lstrcpy,addr bufferx,StrAddr("FirmWare: ")
;				invoke P2K_ReadFW
;				mov esi,offset Cmd_Recv_Buf
;				push esi
;				mov eax,[Cmd_Recv_Size]
;				add esi,eax
;				mov byte ptr [esi],0
;				pop esi
;				inc esi
;				invoke lstrcat,addr bufferx,esi
;				invoke logstat,addr bufferx

				jmp @@exit
				                
GetVolInfo      endp
GetVolInfoShort proc near
				; volume
				invoke GetMsgAddr,78
                invoke lstrcpy,addr bufferx,eax ;addr szName
                invoke lstrcat,addr bufferx,StrAddr ("/")
				invoke SetStatusText, 1, 0, ADDR bufferx		
				; model
				invoke ezxname
				invoke GetMsgAddr,77
                invoke lstrcpy,addr bufferx,eax 
                invoke lstrcat,addr bufferx,addr EzxModel
				invoke SetStatusText, 3, 0, ADDR bufferx
				; restore progressbar to zero
				invoke SendMessage,hBar,PBM_SETPOS,0,0
				; partitions
				mov CBIndex,5
				.while CBIndex!=0
					invoke SendMessage,hLB1,CB_DELETESTRING,0,0
					invoke SendMessage,hLB2,CB_DELETESTRING,0,0
					dec CBIndex
				.endw
				invoke SendMessage,hLB1,CB_INSERTSTRING,0,StrAddr("  /*")
				invoke SendMessage,hLB1,CB_INSERTSTRING,1,StrAddr("  /ezxlocal/*")
				invoke SendMessage,hLB1,CB_INSERTSTRING,2,StrAddr("  /usr/data_resource/*")
				invoke SendMessage,hLB1,CB_INSERTSTRING,3,StrAddr("  /mmc/mmca1/*")
				invoke SendMessage,hLB1,CB_INSERTSTRING,4,StrAddr("P2k phone seems")
				invoke SendMessage,hLB2,CB_INSERTSTRING,0,StrAddr("  /*")
				invoke SendMessage,hLB2,CB_INSERTSTRING,1,StrAddr("  /ezxlocal/*")
				invoke SendMessage,hLB2,CB_INSERTSTRING,2,StrAddr("  /usr/data_resource/*")
				invoke SendMessage,hLB2,CB_INSERTSTRING,3,StrAddr("  /mmc/mmca1/*")
				invoke SendMessage,hLB2,CB_INSERTSTRING,4,StrAddr("P2k phone seems")
				mov CBIndex,0
				.while CBIndex!=5
					invoke SendMessage,hLB1,CB_SETITEMDATA,CBIndex,P2kIconIndex
					invoke SendMessage,hLB2,CB_SETITEMDATA,CBIndex,P2kIconIndex
					inc CBIndex
				.endw
				ret
GetVolInfoShort endp

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;             FSAC IO Section - partially unparsed
;
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

P2K_Suspend       proc near
                  mov     byte ptr Cmd_Send_Buf, 0
                  push    offset Cmd_Recv_Size
                  push    offset Cmd_Recv_Buf
                  push    1
                  push    offset Cmd_Send_Buf
                  push    0036h                   ; SUSPEND
                  call    P2K_SendCommand
                  retn
P2K_Suspend       endp

P2K_Restart       proc near
                  push    offset Cmd_Recv_Size
                  push    offset Cmd_Recv_Buf
                  push    0
                  push    offset Cmd_Send_Buf
                  push    0022h                  ; RESTART
                  call    P2K_SendCommand
                  retn
P2K_Restart       endp

P2K_VibrateOn     proc near
                  mov     word ptr Cmd_Send_Buf, 1
                  push    offset Cmd_Recv_Size
                  push    offset Cmd_Recv_Buf
                  push    2
                  push    offset Cmd_Send_Buf
                  push    0096h                  ; VIBRATE on
                  call    P2K_SendCommand
                  retn
P2K_VibrateOn     endp
P2K_VibrateOff    proc near
                  mov     word ptr Cmd_Send_Buf, 0
                  push    offset Cmd_Recv_Size
                  push    offset Cmd_Recv_Buf
                  push    2
                  push    offset Cmd_Send_Buf
                  push    0096h                  ; VIBRATE off
                  call    P2K_SendCommand
                  retn
P2K_VibrateOff    endp
P2K_Vibrate     proc near
				invoke P2K_VibrateOn
				invoke Sleep,100	 
				invoke P2K_VibrateOff	 
P2K_Vibrate	    endp
P2K_ReadFW    proc near
                  mov     word ptr Cmd_Send_Buf, 0ffffh
                  push    offset Cmd_Recv_Size
                  push    offset Cmd_Recv_Buf
                  push    2
                  push    offset Cmd_Send_Buf
                  push    0039h                  
                  call    P2K_SendCommand
                  retn
P2K_ReadFW    endp

;===================FSAC IO======================
;+--------------------------------+
;  Open File in P2K phone - cmd 0

FSAC_open       proc near

arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp

                push    esi
                push    ebx
                push    ecx

                mov     edi, offset Cmd_Send_Buf
                mov     Cmd_Recv_Size, 0

                mov     eax, [ebp+arg_4]
                .if isUSBLAN==3
	                mov 	P2kFileattribOU,eax 	; save attrib while opening file
	            	mov eax,0ffffffffh    
	            .endif    
                xchg    ah, al
                rol     eax, 10h
                xchg    ah, al
                mov     dword ptr [edi+04h], eax
                mov     dword ptr [edi+00h], 0 ; Cmd 0 - Open

                push    [ebp+arg_0]
                call    lstrlenA
                cmp     eax, 0
                jz      @@fail
                mov     ecx, FileList_RecSize
                sub     ecx, 8
                cmp     eax, ecx
                ja      @@fail
                push    edi

                add     edi, 8
                mov     esi, [ebp+arg_0] ; fname
                xor     edx, edx
@@name_cpy_loop:
                mov     cl, [esi+edx]
                mov     [edi+edx], cl
                inc     edx
                cmp     edx, eax
                jl      short @@name_cpy_loop
                pop     edi

                push    offset Cmd_Recv_Size
                push    offset Cmd_Recv_Buf
                add     eax, 8
                push    eax ; in data size - name len+8
                push    offset Cmd_Send_Buf
                push    004Ah                   ; FSAC
                
				mov eax,Cmd_Send_Size
				mov esi,offset Cmd_Send_Buf
				mov eax,[esi]
				mov ebx,[esi+4]
				mov ecx,[esi+8]
				mov edx,[esi+12]
				mov edi,[esi+16]
				nop
                
                call    P2K_SendCommand
                cmp     eax, 0
                jnz     @@fail
                cmp     Cmd_Recv_Size, 1
                jnz     short @@exit
                cmp     byte ptr Cmd_Recv_Buf, 0
                jnz     short @@exit
                xor     eax, eax
                jmp     @@exit
@@fail:
                mov     eax, -1
@@exit:
                pop     ecx
                pop     ebx
                pop     esi
                leave
                retn    8
FSAC_open       endp

;+----------------------------------+
;  Read File from P2K phone - cmd 1

FSAC_read       proc near

                push    ebp
                mov     ebp, esp

                push    ecx
                push    ebx
                push    esi
                push    edi
				
				mov 	P2kFilesize,0
                mov     dword ptr Cmd_Send_Buf, 01000000h

                mov     eax, [ebp+arg_4] ; size
                cmp     eax, 0
                jz      @@fail
                mov     edi, eax
                mov     ebx, eax
                and     ebx, 3FFh       ; bytes in last block
                shr     edi, 0Ah        ; /400h - full blocks count
                mov     ecx, 400h ; block size
;                mov     Cmd_Recv_Size, ecx ; ?????

                mov     FSAC_Read_Bufs_Copyed, 0
                mov     FSAC_Read_BufPos, 0
                test    edi, edi
                jnz     @@not_below_buf ; full blocks present
                xchg    ah, al
                rol     eax, 10h
                xchg    ah,al
                mov     dword ptr Cmd_Send_Buf+04h, eax
                jmp     @@loop
@@not_below_buf:
                mov     dword ptr Cmd_Send_Buf+04h, 00040000h

@@loop:			

				mov 	eax,dword ptr  Cmd_Send_Buf+04h
                push    offset Cmd_Recv_Size
                push    offset Cmd_Recv_Buf
                push    8
                push    offset Cmd_Send_Buf
                push    004Ah                   ; FSAC
                call    P2K_SendCommand

                cmp     eax, 0
                jnz     @@fail

				invoke SendDlgItemMessage,hWinV,1014,PBM_STEPIT,0,0

                inc     FSAC_Read_Bufs_Copyed ; 0 at first loop

                mov     ecx, Cmd_Recv_Size
                xor     esi, esi
                test    cx, cx
                jbe     short @@buf_copyed
                mov     eax, FSAC_Read_BufPos
                push    edi
                mov     edi, [ebp+arg_0]
@@buf_loop:
                mov     cl, byte ptr [Cmd_Recv_Buf+esi]
                mov     [edi+eax], cl

                mov     ecx, Cmd_Recv_Size
                inc     esi
                inc     eax
                and     ecx, 0FFFFh
                cmp     esi, ecx
                jl      short @@buf_loop
                mov     FSAC_Read_BufPos, eax
                pop     edi

@@buf_copyed:	
                mov     edx, FSAC_Read_Bufs_Copyed
                and     edx, 0FFFFh
                cmp     edx, edi
                jnz     short @@skip_lastread_size
                and     ebx, 0FFFFh
                xchg    bh, bl
                rol     ebx, 10h
                xchg    bh, bl
                mov     dword ptr Cmd_Send_Buf+04h, ebx

@@skip_lastread_size:
                mov     ecx, Cmd_Recv_Size
                add P2kFilesize,ecx
                cmp     cx, 400h
                jz      @@loop
@@exit:
                mov     esi, 0
                cmp     cx, 1
                jnz     short @@exit_ok
;                cmp     Cmd_Recv_Buf, cl
;                jnz     short @@exit_ok
@@fail:
                mov     esi, -1
                mov P2kFilesize,0
@@exit_ok:		
                mov     eax, esi
                pop     edi
                pop     esi
                pop     ebx
                pop     ecx
                leave
                retn    8
FSAC_read       endp

;+-----------------------------+
;  Write file to Phone - cmd 2

FSAC_write      proc near

arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    edx
                push    ebx
                push    esi
                push    edi
                
   				invoke CreateMutex, NULL, FALSE, addr SuspendP2kA
				mov hSMutex,eax
                
                xor     esi, esi
                mov     dword ptr Cmd_Send_Buf+0, 02000000h ; Cmd
                mov     Cmd_Recv_Size, 0
                mov     byte ptr Cmd_Recv_Buf, 0

                mov     ebx, [ebp+arg_4] ; Size

@@loop1:
				invoke SendDlgItemMessage,hWinV,1014,PBM_STEPIT,0,0

                xor     eax, eax
                mov     edi, [ebp+arg_0] ; buff addr

                cmp     ebx, 0
                jz      @@block_wr_ok
                cmp     ebx, 400h ; mstapi uses this buf size...
                jb      short @@last_block

                mov     edx, 400h
                jmp     @@loop_datacopy
@@toloop1:      jmp short @@loop1
@@last_block:
                mov     edx, ebx
                ; copy chunk data into sendcommand buffer
                ; edx: bytes to copy 400h or less
                ; eax: 0 dest index
                ; edi: source
                ; esi: 0 src index
                ; buff will be: cmd,size,data
@@loop_datacopy:
                push    edx
                xchg    dh, dl
                rol     edx, 10h
                xchg    dh, dl
                mov     dword ptr Cmd_Send_Buf+4, edx ; chunk size
                pop     edx

                mov     cl, [edi+esi]
                mov     byte ptr [Cmd_Send_Buf+8+eax], cl
                inc     eax
                inc     esi
                cmp     eax, edx
                jl      short @@loop_datacopy
                ; buffer ready
                push    offset Cmd_Recv_Size
                push    offset Cmd_Recv_Buf
                add     edx, 8		; header size
                push    edx
                push    offset Cmd_Send_Buf
                push    004Ah                   ; FSAC
                call    P2K_SendCommand
                cmp     eax, 0
                jnz     @@block_wr_fail
				; check answer, p2k05: there is diff answer!!!
				;mov ax,word ptr Cmd_Recv_Size
				;mov bl,byte ptr Cmd_Recv_Buf
                cmp     word ptr Cmd_Recv_Size, 1
                jnz     short @@block_wr_ok
                cmp     byte ptr Cmd_Recv_Buf, 6
                jnz     short @@block_wr_fail
@@block_wr_ok:
                mov     eax, 0
                sub     edx, 8
                sub     ebx, edx
                jz      @@exit
                jmp     short @@toloop1

@@block_wr_fail:
                mov     eax, -1
@@exit:
				invoke CloseHandle,hSMutex

                pop     edi
                pop     esi
                pop     ebx
                pop     edx
                leave
                retn    8
FSAC_write      endp

;+----------------------------+
;  Seek file in Phone - cmd 3

FSAC_seek       proc near

arg_0           = dword ptr  8
arg_4           = byte ptr  0Ch

                push    ebp
                mov     ebp, esp

                mov     dword ptr Cmd_Send_Buf, 03000000h ; Cmd

                mov     eax, [ebp+arg_0]
                xchg    ah, al
                rol     eax, 10h
                xchg    ah, al
                mov     dword ptr Cmd_Send_Buf+4, eax
                mov     al, [ebp+arg_4]
                mov     byte ptr Cmd_Send_Buf+8, al
                mov     Cmd_Recv_Size, 0
                mov     byte ptr Cmd_Recv_Buf, 0
                push    offset Cmd_Recv_Size
                push    offset Cmd_Recv_Buf
                push    9
                push    offset Cmd_Send_Buf
                push    004Ah                   ; FSAC
                call    P2K_SendCommand
                cmp     eax, 0
                jnz     @@fail
                cmp     word ptr Cmd_Recv_Size, 1
                jz      @@fail
                cmp     byte ptr Cmd_Recv_Buf, 1
                jz      @@fail
                xor     eax, eax
                jmp     @@exit
@@fail:
                mov     eax, -1
@@exit:
                leave
                retn    8
FSAC_seek       endp

;+---------------------------------+
;  Close file in P2K Phone - cmd 4

FSAC_close      proc near
                mov     Cmd_Recv_Size, 0
                mov     byte ptr Cmd_Recv_Buf, 0
                mov     dword ptr Cmd_Send_Buf, 04000000h ; Cmd
                push    offset Cmd_Recv_Size
                push    offset Cmd_Recv_Buf
                push    4
                push    offset Cmd_Send_Buf
                push    004Ah                   ; FSAC
                call    P2K_SendCommand
                cmp     eax, 0
                jnz     @@fail
                cmp     word ptr Cmd_Recv_Size, 1
                jz      @@fail
                cmp     byte ptr Cmd_Recv_Buf, 1
                jz      @@fail
                xor     eax, eax
                jmp     @@exit
@@fail:
                mov     eax, -1
@@exit:
                retn
FSAC_close      endp

;+--------------------------------+
;  Delete file from phone - cmd 5

FSAC_delete     proc near

arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp

                push    esi
                push    edx
                push    ecx

                mov     Cmd_Recv_Size, 0
                mov     byte ptr Cmd_Recv_Buf, 0
                mov     dword ptr Cmd_Send_Buf, 05000000h ; Cmd
                mov     esi, [ebp+arg_0]
                push    esi
                call    lstrlenA
                xor     edx, edx
                cmp     eax, 0
                jz      @@fail
                mov     ecx, FileList_RecSize
                sub     ecx, 8
                cmp     eax, ecx
                ja      @@exit

@@name_cpy_loop:
                mov     cl, [esi+edx]
                mov     byte ptr [Cmd_Send_Buf+4+edx], cl
                inc     edx
                cmp     edx, eax
                jl      short @@name_cpy_loop
                push    offset Cmd_Recv_Size
                push    offset Cmd_Recv_Buf
                add     eax, 4
                push    eax
                push    offset Cmd_Send_Buf
                push    004Ah                   ; FSAC
                call    P2K_SendCommand
                cmp     eax, 0
                jnz     @@fail
                cmp     Cmd_Recv_Size, 1
                jz      @@fail
                cmp     Cmd_Recv_Buf, 1
                jz      @@fail
                xor     eax, eax
                jmp     @@exit
@@fail:
                mov     eax, -1
@@exit:
                pop     ecx
                pop     edx
                pop     esi

                leave
                retn    4
FSAC_delete     endp
;+--------------------------------+
;  Make dir into phone - cmd e

FSAC_makedir    proc near

arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp

                push    esi
                push    ebx
                push    ecx

                mov     edi, offset Cmd_Send_Buf
                mov     Cmd_Recv_Size, 0

                mov     eax, [ebp+arg_4]
                xchg    ah, al
                rol     eax, 10h
                xchg    ah, al
                .if isUSBLAN==3
	                mov 	P2kFileattribOU,eax 	; save attrib while opening file
	            	mov eax,0ffffffffh    
	            .endif    
                mov     dword ptr [edi+04h], eax
                mov     dword ptr [edi+00h], 0E000000h ; Cmd e - mkdir

                push    [ebp+arg_0]
                call    lstrlenA
                cmp     eax, 0
                jz      @@fail
                mov     ecx, FileList_RecSize
                sub     ecx, 8
                cmp     eax, ecx
                ja      @@fail
                push    edi

                add     edi, 8
                mov     esi, [ebp+arg_0] ; fname
                xor     edx, edx
@@name_cpy_loop:
                mov     cl, [esi+edx]
                mov     [edi+edx], cl
                inc     edx
                cmp     edx, eax
                jl      short @@name_cpy_loop
                pop     edi

                push    offset Cmd_Recv_Size
                push    offset Cmd_Recv_Buf
                add     eax, 8
                push    eax ; in data size - name len+8
                push    offset Cmd_Send_Buf
                push    004Ah                   ; FSAC

				mov esi,offset Cmd_Send_Buf
				mov eax,[esi]
				mov ebx,[esi+4]
				mov ecx,[esi+8]
				mov edx,[esi+12]
				mov edi,[esi+16]
				nop

                call    P2K_SendCommand
                cmp     eax, 0
                jnz     @@fail
                cmp     Cmd_Recv_Size, 1
                jnz     short @@exit
                cmp     byte ptr Cmd_Recv_Buf, 0
                jnz     short @@exit
                xor     eax, eax
                jmp     @@exit
@@fail:
                mov     eax, -1
@@exit:
                pop     ecx
                pop     ebx
                pop     esi
                leave
                retn    8
FSAC_makedir    endp
;+--------------------------------+
;  Delete dir into phone - cmd f

FSAC_deldir    proc near

arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp

                push    esi
                push    ebx
                push    ecx

                mov     edi, offset Cmd_Send_Buf
                mov     Cmd_Recv_Size, 0

                mov     eax, [ebp+arg_4]
                xchg    ah, al
                rol     eax, 10h
                xchg    ah, al
                .if isUSBLAN==3
	                mov 	P2kFileattribOU,eax 	; save attrib while opening file
	            	mov eax,0ffffffffh    
	            .endif    
                mov     dword ptr [edi+04h], eax
                mov     dword ptr [edi+00h], 0F000000h ; Cmd e - mkdir

                push    [ebp+arg_0]
                call    lstrlenA
                cmp     eax, 0
                jz      @@fail
                mov     ecx, FileList_RecSize
                sub     ecx, 8
                cmp     eax, ecx
                ja      @@fail
                push    edi

                add     edi, 8
                mov     esi, [ebp+arg_0] ; fname
                xor     edx, edx
@@name_cpy_loop:
                mov     cl, [esi+edx]
                mov     [edi+edx], cl
                inc     edx
                cmp     edx, eax
                jl      short @@name_cpy_loop
                pop     edi

                push    offset Cmd_Recv_Size
                push    offset Cmd_Recv_Buf
                add     eax, 8
                push    eax ; in data size - name len+8
                push    offset Cmd_Send_Buf
                push    004Ah                   ; FSAC

				mov esi,offset Cmd_Send_Buf
				mov eax,[esi]
				mov ebx,[esi+4]
				mov ecx,[esi+8]
				mov edx,[esi+12]
				mov edi,[esi+16]
				nop

                call    P2K_SendCommand
                cmp     eax, 0
                jnz     @@fail
                cmp     Cmd_Recv_Size, 1
                jnz     short @@exit
                cmp     byte ptr Cmd_Recv_Buf, 0
                jnz     short @@exit
                xor     eax, eax
                jmp     @@exit
@@fail:
                mov     eax, -1
@@exit:
                pop     ecx

                pop     ebx
                pop     esi
                leave
                retn    8
FSAC_deldir    endp
; ----------------------------------------------------

; Clear - what? :) PST don't use this function - cmd 6

FSAC_clear      proc near

arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp

                mov     al, byte ptr [ebp+arg_0]
                mov     byte ptr Cmd_Send_Buf+4, al

                mov     Cmd_Recv_Size, 0
                mov     byte ptr Cmd_Recv_Buf, 0
                mov     dword ptr Cmd_Send_Buf, 06000000h ; Cmd

                push    offset Cmd_Recv_Size
                push    offset Cmd_Recv_Buf
                push    5
                push    offset Cmd_Send_Buf
                push    004Ah                   ; FSAC
                call    P2K_SendCommand
                cmp     eax, 0
                jnz     @@fail
                cmp     Cmd_Recv_Size, 1
                jz      @@fail
                cmp     Cmd_Recv_Buf, 1
                jz      @@fail
                xor     eax, eax
                jmp     @@exit
@@fail:
                mov     eax, -1
@@exit:
                leave
                retn    4
FSAC_clear      endp


;+-------------------------+
;  Get File list - cmd 7,8

FSAC_search_file  proc near
                push    ebp
                mov     ebp, esp
                push    ecx
                push    edx
                push    ebx
                push    esi
                push    edi
                ; fill 256 zero
                mov ecx,100h/4
               	mov edi,offset Cmd_Send_Buf
                .while ecx!=0
                	mov dword ptr [edi],0
                	add edi,4
                	dec ecx
                .endw	
; Request files count
                mov     word ptr Cmd_Recv_Buf, -1
                mov     dword ptr Cmd_Send_Buf, 07000000h ; Cmd
                ;mov byte ptr Cmd_Send_Buf+4,00
                mov byte ptr Cmd_Send_Buf+5,2fh
                ;mov byte ptr Cmd_Send_Buf+6,00
                mov al,Partition
                mov byte ptr Cmd_Send_Buf+7,al ;62h
                ;mov byte ptr Cmd_Send_Buf+8,00
                mov byte ptr Cmd_Send_Buf+9,2fh
                mov byte ptr Cmd_Send_Buf+10,0ffh
                mov byte ptr Cmd_Send_Buf+11,0feh
                ;mov byte ptr Cmd_Send_Buf+12,00
                mov byte ptr Cmd_Send_Buf+13,2ah
                push    offset Cmd_Recv_Size
                push    offset Cmd_Recv_Buf
                push    100h ;4
                push    offset Cmd_Send_Buf
                push    004Ah                   ; FSAC
                call    P2K_SendCommand
                cmp     eax, 0
                jnz     @@fail
                cmp     word ptr Cmd_Recv_Size, 2
                jb      @@fail
                cmp     word ptr Cmd_Recv_Buf, 0
                jbe     @@err_files_num                  ; nothing to search
                cmp     word ptr Cmd_Recv_Buf, -1
                jnz     @@files_num_ok
@@err_files_num:
                ;push    offset str_filesnum
                ;call    logstat
                invoke GetMsgAddr,34
                invoke logstat,eax ;addr str_filesnum
                jmp     @@fail

@@files_num_ok:
; Motorola Little-Endian convert...
                mov     ax, word ptr Cmd_Recv_Buf
                xchg    ah, al
		        mov     Files_found, eax
                mov     edi, eax
				inc eax ;5vi
				inc eax ;5vi
; Alloc mem for buffer
				.if isRefresh==1
	                mov     ecx, 110h ; - entry size+enties count...
	                mul     ecx
	                push    eax
	                push    40h
					mov SearchBuf_Size,eax
	                call    GlobalAlloc
	                cmp     eax, 0
	                jnz     @@malloc_ok
	
	                ;push    offset str_malloc_fail
	                ;call    logstat
                	invoke GetMsgAddr,35
	                invoke logstat,eax ;addr str_malloc_fail
	                jmp     @@fail
@@malloc_ok:
	                mov     SearchBuf_Ptr, eax
	                mov     SearchBuf_Pos, eax
                .endif
				jmp @@exit                
                
; progress
;                mov     eax, Files_found
;                rol     eax, 10h
;                push    eax
;                push    0
;                push    401h
;                push    1018
;                push    [ebp+arg_0]
;                call    SendDlgItemMessageA
;
;                push    0
;                push    0
;                push    402h
;                push    1018
;                push    [ebp+arg_0]
;                call    SendDlgItemMessageA
				
@@loop:			
;; request block of records
                mov     word ptr Cmd_Recv_Buf, -1
                mov     dword ptr Cmd_Send_Buf, 08000000h ; Cmd
                
                mov byte ptr Cmd_Send_Buf+4,1 ; extra byte snipped from mck
                
                push    offset Cmd_Recv_Size
                push    SearchBuf_Pos
                push    5 ;4				 ; size is 5 instead 4 , snipped from mck
                push    offset Cmd_Send_Buf
                push    004Ah                   ; FSAC
                
                call    P2K_SendCommand

                cmp     eax, 0
                jnz     @@fail

                mov     eax, Cmd_Recv_Size
                sub     eax, 4
                cdq
                mov     ecx, 2Ch
                mov     FileList_RecSize, ecx
                idiv    ecx
                cmp     edx, 0
                jz      @@rec_ok

                mov     eax, Cmd_Recv_Size
                sub     eax, 4
                cdq
                mov     ecx, 10Ch
                mov     FileList_RecSize, ecx
                idiv    ecx
                cmp     edx, 0
                jz      @@rec_ok
                mov     edx, 0
                mov     FileList_RecSize, edx
;;                push    offset msg_fl_rec_size_fail
;;                call    logstat
                invoke GetMsgAddr,36
                invoke logstat,eax ;addr msg_fl_rec_size_fail
                jmp     @@fail

@@rec_ok:
                mov     eax, SearchBuf_Pos
                movzx   eax, word ptr [eax] ; records readed
                xchg    ah, al
                sub     edi, eax

;; progress
;                mov     eax, Files_found
;                sub     eax, edi
;                push    0
;                push    eax
;                push    402h
;                push    1018
;                push    [ebp+arg_0]
;                call    SendDlgItemMessageA
;
                mov     eax, Cmd_Recv_Size
                add     SearchBuf_Pos, eax
                
;                test    di, di
;                ja      @@loop
;
;                mov     eax, 0
;                jmp     @@exit
@@fail:
                mov     eax, -1
@@exit:
                pop     edi
                pop     esi
                pop     ebx
                pop     edx
                pop     ecx
                leave
                retn    4
FSAC_search_file  endp

File_CountEx      proc near

arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                push    edx
                push    ebx
                push    esi
                push    edi
                
                mov     edi, [ebp+arg_0]          ; edi - search mask:  /b/*.*
                mov     esi, offset Cmd_Send_Buf
                mov     ecx, 4                    ; ecx - offset in Cmd_Send_Buf
                xor     eax, eax                  ; eax - offset in mask


@@again1:       cmp byte ptr [edi+eax], '*'
                jz      @@end_of_path
                mov     byte ptr [esi+ecx], 0
                inc     ecx
                mov     bl, [edi+eax]
                mov     [esi+ecx], bl
                inc     eax
                inc     ecx
                jmp     @@again1

@@end_of_path:                
               
               ; mov     word ptr [esi+ecx], 0FEFFh
               ; add     ecx,2

@@again:        cmp     byte ptr [edi+eax], 0
                jz      @@end_of_mask
                mov     byte ptr [esi+ecx], 0
                inc     ecx
                mov     bl, [edi+eax]
                mov     [esi+ecx], bl
                inc     eax
                inc     ecx
                jmp     @@again
@@end_of_mask:
                mov     word ptr [esi+ecx], 0
                add     ecx,2
                
                
; Request files count
                ;cmp     TCI_IF, -1
                ;jz      @@fail

                mov     word ptr Cmd_Recv_Buf, -1
                mov     dword ptr Cmd_Send_Buf, 07000000h ; Cmd
                push    offset Cmd_Recv_Size
                push    offset Cmd_Recv_Buf
                push    ecx
                push    offset Cmd_Send_Buf
                push    004Ah                   ; FSAC
                ;push    TCI_IF
                call    P2K_SendCommand
                cmp     eax, 0
                jnz     @@fail
                cmp     word ptr Cmd_Recv_Size, 2
                jb      @@fail
                cmp     word ptr Cmd_Recv_Buf, 0
                jbe     @@fail                           ; nothing to search
                cmp     word ptr Cmd_Recv_Buf, -1
                jz      @@fail

                xor     eax, eax
                mov     ax, word ptr Cmd_Recv_Buf
                xchg    ah, al
		        mov     Files_found, eax
                mov     edi, eax
				inc eax ;5vi
				inc eax ;5vi
; Alloc mem for buffer
				.if isRefresh==1
	                mov     ecx, 110h ; - entry size+enties count...
	                mul     ecx
	                push    eax
	                push    40h
					mov SearchBuf_Size,eax
	                call    GlobalAlloc
	                cmp     eax, 0
	                jnz     @@malloc_ok
	
	                ;push    offset str_malloc_fail
	                ;call    logstat
                	invoke GetMsgAddr,35
	                invoke logstat,eax ;addr str_malloc_fail
	                jmp     @@fail
@@malloc_ok:
	                mov     SearchBuf_Ptr, eax
	                mov     SearchBuf_Pos, eax
                .endif
				jmp @@exit                
@@fail:
                mov     eax, -1
@@exit:
                pop     edi
                pop     esi
                pop     ebx
                pop     edx
                pop     ecx
                leave
                retn  4
File_CountEx      endp

File_CountOld   proc near

                push    ebp
                mov     ebp, esp
                push    ecx
                push    edx
                push    ebx
                push    esi
                push    edi
; Request files count
                ;cmp     TCI_IF, -1
                ;jz      @@fail

                mov     word ptr Cmd_Recv_Buf, -1
                mov     dword ptr Cmd_Send_Buf, 07000000h ; Cmd
                push    offset Cmd_Recv_Size
                push    offset Cmd_Recv_Buf
                push    4
                push    offset Cmd_Send_Buf
                push    004Ah                   ; FSAC
                ;push    TCI_IF
                call    P2K_SendCommand
                cmp     eax, 0
                jnz     @@fail
                cmp     word ptr Cmd_Recv_Size, 2
                jb      @@fail
                cmp     word ptr Cmd_Recv_Buf, 0
                jbe     @@fail                           ; nothing to search
                cmp     word ptr Cmd_Recv_Buf, -1
                jz      @@fail

                xor     eax, eax
                mov     ax, word ptr Cmd_Recv_Buf
                xchg    ah, al
		        mov     Files_found, eax
                mov     edi, eax
				inc eax ;5vi
				inc eax ;5vi
; Alloc mem for buffer
				.if isRefresh==1
	                mov     ecx, 110h ; - entry size+enties count...
	                mul     ecx
	                push    eax
	                push    40h
					mov SearchBuf_Size,eax
	                call    GlobalAlloc
	                cmp     eax, 0
	                jnz     @@malloc_ok
	
	                ;push    offset str_malloc_fail
	                ;call    logstat
                	invoke GetMsgAddr,35
	                invoke logstat,eax ;addr str_malloc_fail
	                jmp     @@fail
@@malloc_ok:
	                mov     SearchBuf_Ptr, eax
	                mov     SearchBuf_Pos, eax
                .endif
				jmp @@exit                
@@fail:
                mov     eax, -1
@@exit:
                pop     edi
                pop     esi
                pop     ebx
                pop     edx
                pop     ecx
                leave
                retn
File_CountOld   endp
File_Count proc FilFil:DWORD
			;**************************
			; Branch here P2kOverUsblan
			;**************************
			.if isCDMA==1
				push FilFil
				invoke File_CountEx
				ret
			.endif
			.if isUSBLAN==3
				.if isFileFilter==1
					mov esi, FilFil
					add esi,2
					push esi
					invoke File_CountEx
				.else
					invoke File_CountOld
				.endif		
			.else	
				.if isFileFilter==1
					push FilFil
					invoke File_CountEx
				.else
					push FilFil
					invoke FSAC_search_file
				.endif
			.endif	
		ret
File_Count endp
;+-------------------------+
;  Get root name - cmd 0xA

FSAC_GetVolName proc

arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp

                push    ecx
                push    esi
                push    edi

                mov     esi, [ebp+arg_0]
                mov     ecx, 80h
                xor     eax, eax
                mov     edi, esi
loop5vi:                ;repe stosd
				stosd
				loop loop5vi
                mov     word ptr Cmd_Recv_Buf, 0
                mov     dword ptr Cmd_Send_Buf, 0A000000h ; Cmd

                push    offset Cmd_Recv_Size
                push    esi
                push    4
                push    offset Cmd_Send_Buf
                push    004Ah                   ; FSAC
                call    P2K_SendCommand
                cmp     eax, 0
                jnz     @@fail
                cmp     word ptr Cmd_Recv_Size, 1
                jz      @@fail
                cmp     byte ptr [esi], 6
                jz      @@fail
                xor     eax, eax
                jmp     @@exit
@@fail:
                mov     eax, -1
@@exit:

                pop     edi
                pop     esi
                pop     ecx

                leave
                retn    4
FSAC_GetVolName endp

FSAC_volume_space proc near

arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp

                push    ecx
                push    edx
                push    ebx
                push    esi
                push    edi
                mov     edi, offset Cmd_Send_Buf
                mov     ecx, 80h
                xor     eax, eax
                rep stosd

                mov     byte ptr Cmd_Recv_Buf, 0
                mov     dword ptr Cmd_Send_Buf, 0B000000h ; Cmd
                mov     edi, offset Cmd_Send_Buf
                add     edi, 4
                mov     esi, [ebp+arg_0]
@@loop:
                lodsw
                cmp     ax, 0
                jz      @@go_fsac
                stosw
                inc     ecx
                cmp     ecx, 80h
                jl      short @@loop

@@go_fsac:
                mov     VolSpace, 0
                push    offset Cmd_Recv_Size
                push    offset Cmd_Recv_Buf
                push    200h
                push    offset Cmd_Send_Buf
                push    004Ah                   ; FSAC
                call    P2K_SendCommand
                cmp     eax, 0
                jnz     @@fail
                cmp     word ptr Cmd_Recv_Size, 1
                jz      @@fail
                cmp     byte ptr [esi], 6
                jz      @@fail
                mov     edx, dword ptr Cmd_Recv_Buf
                xchg    dh, dl
                rol     edx, 10h
                xchg    dh, dl
                mov     VolSpace, edx
                cmp     edx, 0
                jnz     @@ok
                ;push    offset msg_volsize_zero
                ;call    logstat
                invoke GetMsgAddr,19
                invoke logstat,eax ;addr msg_volsize_zero
                jmp     @@fail
@@ok:
                xor     eax, eax
                jmp     @@exit
@@fail:			
                mov     eax, -1
                .if isUSBLAN==3
    	            xor     eax, eax
                .endif
@@exit:
                pop     edi
                pop     esi
                pop     ebx
                pop     edx
                pop     ecx
                leave
                retn    4
FSAC_volume_space endp

;------------- SEEM IO ----------------

;Write_Seem   proc near
;
;arg_0           = dword ptr  8
;
;                push    ebp
;                mov     ebp, esp
;
;
;                push    offset str_loadseem
;                call    logstat
;
;; Seem no
;                push    10h
;                push    offset str_buf
;                push    1013
;                push    [ebp+arg_0]
;                call    GetDlgItemTextA
;
;                push    offset str_buf
;                call    HexStr2Int
;                cmp     eax,0FFFFh
;                jb      @@seem_ok
;                mov     eax, 0FFFFh
;@@seem_ok:
;                mov     seem_no, eax
;                push    eax
;                push    offset str_hexdw
;                push    offset str_buf
;                call    wsprintfA
;                add     esp, 0Ch
;
;                push    offset str_buf
;                push    1013
;                push    [ebp+arg_0]
;                call    SetDlgItemTextA
;
;                push    offset  str_buf
;                call    logstat
;; Rec no
;                push    10h
;                push    offset str_buf
;                push    1014
;                push    [ebp+arg_0]
;                call    GetDlgItemTextA
;
;                push    offset str_buf
;                call    HexStr2Int
;
;                cmp     eax,0FFFFh
;                jb      @@rec_ok1
;                mov     eax, 1h
;@@rec_ok1:
;                cmp     eax,0
;                ja      @@rec_ok
;                mov     eax, 1h
;@@rec_ok:
;                mov     rec_no, eax
;                push    eax
;                push    offset str_hexdw
;                push    offset str_buf

;                call    wsprintfA
;                add     esp, 0Ch
;
;                push    offset str_buf
;                push    1014
;                push    [ebp+arg_0]
;                call    SetDlgItemTextA
;
;                push    offset  str_rec
;                call    logstat
;
;                push    offset  str_buf
;                call    logstat
;; get seem size
;                push    offset seem_buf
;                push    0
;                push    0
;                push    rec_no
;                push    seem_no
;                call    Cmd_RDELEM
;                cmp     eax, 0
;                jnz     @@fail
;                cmp     byte ptr seem_buf, 0
;                jnz     @@fail
;
;                dec     seem_read_bytes
;
;                mov     fname_buf, 0
;                mov     fname_t_buf, 0
;                mov     OFN_Flags, 0
;                push    offset OpenFileNameSize
;                call    GetOpenFileNameA
;
;                push    -1
;                push    0
;                push    3 ; open existing
;                push    0
;                push    0
;                push    0C0000000h ; generic RW
;                push    offset fname_buf
;                call    CreateFileA
;                mov     FHandle, eax
;                cmp     eax,-1
;                jz      @@fail
;
;                push    offset filesize_ex
;                push    eax
;                call    GetFileSize
;                cmp     filesize_ex, 0
;                jnz     @@fail
;                cmp     eax, seem_read_bytes
;                jnz     @@fail
;
;                push    0 ; overlapped
;                push    offset file_readed ; bytes readen
;                push    seem_read_bytes  ; bytes to read
;                push    offset seem_data
;                push    FHandle
;                call    ReadFile
;                cmp     eax, 0
;                jz      @@fail
;                mov     eax, seem_read_bytes
;                cmp     file_readed, eax
;                jnz     @@fail
;
;                push    seem_read_bytes
;                push    0
;                push    rec_no
;                push    seem_no
;                call    Cmd_STELEM
;                cmp     eax, 0
;                jnz     @@fail
;
;                push    FHandle
;                call    CloseHandle
;
;                push    offset  str_ok
;                call    logstat
;
;@@fail:
;                leave
;                retn 4
;
;
;Write_Seem   endp
;
;
;Read_Seem    proc near               ; CODE
;
;arg_0           = dword ptr  8
;                push    ebp
;                mov     ebp, esp
;
;                push    offset str_seem_fn
;                push    offset fname_buf
;                call    lstrcpyA
;
;                push    offset OpenFileNameSize
;                mov     OFN_Flags, 0
;                call    GetSaveFileNameA
;                cmp     eax, 0
;                jz      @@canceled
;
;
;                push    offset str_saveseem
;                call    logstat
;
;
;; Seem from
;                push    10h
;                push    offset str_buf
;                push    1009
;                push    [ebp+arg_0]
;                call    GetDlgItemTextA
;
;                push    offset str_buf
;                call    HexStr2Int
;                cmp     eax,0FFFFh
;                jb      @@from_ok
;                mov     eax, 0FFFFh
;@@from_ok:
;                mov     seem_no, eax
;                push    eax
;                push    offset str_hexdw
;                push    offset str_buf
;                call    wsprintfA
;                add     esp, 0Ch
;
;                push    offset str_buf
;                push    1009
;                push    [ebp+arg_0]
;                call    SetDlgItemTextA
;
;                push    offset  str_buf
;                call    logstat
;; Seem to
;                push    10h
;                push    offset str_buf
;                push    1010
;                push    [ebp+arg_0]
;                call    GetDlgItemTextA
;
;                push    offset str_buf
;                call    HexStr2Int
;                cmp     eax,0FFFFh
;                jb      @@to_ok
;                mov     eax, 0FFFFh
;@@to_ok:
;                mov     seem_to, eax
;                push    eax
;                push    offset str_hexdw
;                push    offset str_buf
;                call    wsprintfA
;                add     esp, 0Ch
;
;                push    offset str_buf
;                push    1010
;                push    [ebp+arg_0]
;                call    SetDlgItemTextA
;
;                push    offset  str_to
;                call    logstat
;
;                push    offset  str_buf
;                call    logstat
;
;                push    offset  crlf
;                call    logstat
;
;                push    offset  str_wait
;                call    logstat
;
;                mov     eax, seem_to
;                rol     eax, 10h
;                add     eax, seem_no
;
;                push    eax
;                push    0
;                push    401h
;                push    1018
;                push    [ebp+arg_0]
;                call    SendDlgItemMessageA
;
;                push    0
;                push    0
;                push    402h
;                push    1018
;                push    [ebp+arg_0]
;                call    SendDlgItemMessageA
;
;                mov     rec_no, 1
;@@loop:
;                push    0
;                push    seem_no
;                push    402h
;                push    1018
;                push    [ebp+arg_0]
;                call    SendDlgItemMessageA
;
;                push    offset seem_buf
;                push    0
;                push    0
;                push    rec_no
;                push    seem_no
;                call    Cmd_RDELEM
;                cmp     eax, 0
;                jnz     @@next
;                cmp     byte ptr seem_buf, 0
;                jnz     @@next
;
;                push rec_no
;                push seem_no
;                push offset str_ctl
;                push offset str_buf
;                call wsprintfA
;                add  esp, 10h
;
;                push    -1
;                push    0
;                push    1 ; Create new
;                push    0
;                push    0
;                push    0C0000000h ; generic RW
;                push    offset str_buf
;                call    CreateFileA
;                mov     FHandle, eax
;;                cmp     eax,0
;;                jz      @@createfail
;
;                push    0
;                push    offset file_readed
;                mov     eax, seem_read_bytes
;                dec     eax
;                push    eax
;                push    offset seem_buf+1
;                push    FHandle
;                call    WriteFile
;;                cmp     eax, 0
;;                jz      @@writefail
;
;                push    FHandle
;                call    CloseHandle
;                inc     rec_no
;                cmp     rec_no,80h
;                jbe     @@loop
;@@next:
;                inc     seem_no
;                mov     rec_no,1
;                mov     eax, seem_to
;                cmp     seem_no, eax
;                jbe     @@loop
;
;                push    offset str_done
;                call    logstat
;@@canceled:
;                leave
;                retn    4
;Read_Seem    endp

Cmd_RDELEM      proc near

arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h
arg_C           = dword ptr  14h
arg_10          = dword ptr  18h

                push    ebp
                mov     ebp, esp

                push    ebx
                push    esi
                push    edi

                mov     eax, [ebp+arg_0] ; seem
                xchg    al, ah
                mov     seem_num, ax

                mov     eax, [ebp+arg_4] ; record
                xchg    al, ah
                mov     seem_rec, ax

                mov     eax, [ebp+arg_8] ; ofs
                xchg    al, ah
                mov     seem_ofs, ax

                mov     eax, [ebp+arg_C] ; bytes
                xchg    al, ah
                mov     seem_bytes, ax


                mov     seem_read_bytes, 1

                push    offset seem_read_bytes
                push    [ebp+arg_10]

                push    8                     ; DataBuf size
                push    offset seem_num

                push    020h           ; COMMAND - RDELEM
                call    P2K_SendCommand
                test    eax, eax
                jnz     @@fail
                mov     eax, 0
                mov     ecx, seem_read_bytes
                cmp     seem_read_bytes, 0
                jbe     short @@ok
                mov     edi, [ebp+arg_10]
                mov     bl, [edi]
                test    bl, bl
                jz      short @@ok
@@fail:
                mov     eax, -1
@@ok:
                pop     edi
                pop     esi
                pop     ebx
                leave
                retn    14h
Cmd_RDELEM      endp

Cmd_STELEM      proc near

arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h
arg_C           = dword ptr  14h

                push    ebp
                mov     ebp, esp

                push    ebx
                push    esi
                push    edi

                mov     eax, [ebp+arg_0] ; seem
                xchg    al, ah
                mov     seem_num, ax

                mov     eax, [ebp+arg_4] ; record
                xchg    al, ah
                mov     seem_rec, ax

                mov     eax, [ebp+arg_8] ; ofs
                xchg    al, ah
                mov     seem_ofs, ax

                mov     eax, [ebp+arg_C] ; bytes
                cmp     eax,0
                ja      @@size_nz
                mov     eax,1
@@size_nz:
                cmp     eax, 2710h
                jna     @@zize_ok
                mov     eax, 2710h
@@zize_ok:
                mov     [ebp+arg_C], eax
                xchg    al, ah
                mov     seem_bytes, ax


                mov     seem_read_bytes, 1

                push    offset seem_read_bytes
                push    offset stelem_result

                mov     eax, [ebp+arg_C] ; bytes
                add     eax, 8
                push    eax                   ; DataBuf size
                push    offset seem_num

                push    02Fh        ; COMMAND STELEM
                call    P2K_SendCommand
                test    eax, eax
                jnz     @@fail2
                mov     eax, 0
                mov     bl, byte ptr stelem_result
                test    bl, bl
                jz      short @@ok
@@fail:
                push ebx
                invoke GetMsgAddr,123
   		        invoke logstat,eax
   		        pop ebx
				invoke dw2ah,ebx,offset str_buf
   		        invoke logstat,addr str_buf
                mov     eax, -1
@@ok:
                pop     edi
                pop     esi
                pop     ebx
                leave
                retn    10h
@@fail2:		      
		        invoke GetMsgAddr,124
   		        invoke logstat,eax
   		        mov eax,-1
                jmp @@ok
                
Cmd_STELEM      endp
Seem_Write      proc near

arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h
arg_C           = dword ptr  14h
arg_10          = dword ptr  18h

                push    ebp
                mov     ebp, esp

                push    ecx
                push    ebx
                push    esi
                push    edi

;                cmp     TCI_IF, -1
;                jz      @@fail

                mov     eax, [ebp+arg_0] ; seem
                xchg    al, ah
                mov     seem_num, ax

                mov     eax, [ebp+arg_4] ; record
                xchg    al, ah
                mov     seem_rec, ax

                mov     eax, [ebp+arg_8] ; ofs
                xchg    al, ah
                mov     seem_ofs, ax

                mov     eax, [ebp+arg_C] ; bytes
                cmp     eax,0
                jbe     @@fail
                cmp     eax, 2710h
                jna     @@zize_ok
                mov     eax, 2710h
@@zize_ok:
                mov     [ebp+arg_C], eax
                xchg    al, ah
                mov     seem_bytes, ax

                mov     esi, [ebp+arg_10]
                mov     edi, offset seem_data
                mov     ecx, [ebp+arg_C]
                rep     movsb

                mov     seem_read_bytes, 0

                push    offset seem_read_bytes
                push    offset stelem_result

                mov     eax, [ebp+arg_C] ; bytes
                add     eax, 8
                push    eax                   ; DataBuf size
                push    offset seem_num

                push    02Fh        ; COMMAND STELEM
;                push    TCI_IF
                call    P2K_SendCommand
                test    eax, eax
                jnz     @@fail2
                mov     eax, 0
                mov     bl, byte ptr stelem_result
                test    bl, bl
                jz      short @@ok
@@fail:
                push ebx
                invoke GetMsgAddr,123
   		        invoke logstat,eax
   		        pop ebx
				invoke dw2ah,ebx,offset str_buf
   		        invoke logstat,addr str_buf
                mov     eax, -1
@@ok:
                pop     edi
                pop     esi
                pop     ebx
                pop 	ecx
                leave
                retn    14h
@@fail2:		      
		        invoke GetMsgAddr,124
   		        invoke logstat,eax
   		        mov eax,-1
                jmp @@ok



;                test    eax, eax
;                jnz     @@fail
;                mov     eax, 0
;                mov     bl, byte ptr stelem_result
;                test    bl, bl
;                jz      short @@ok
;@@fail:
;                mov     eax, -1
;@@ok:
;                pop     edi
;                pop     esi
;                pop     ebx
;                pop     ecx
;                leave
;                retn    14h
Seem_Write      endp


;------------- Old SENDCOMMAND ----------------
; Send any! command to PST.DLL and then - to phone....
; Оставлена для совместимости с процедурками из PST,
; ежели вдруг таковые еще выдирать придется :)
;PST_Send_Command proc near
;
;arg_0           = dword ptr  8
;arg_4           = dword ptr  0Ch
;arg_8           = dword ptr  10h
;arg_C           = dword ptr  14h
;arg_10          = dword ptr  18h
;arg_14          = dword ptr  1Ch
;arg_18          = dword ptr  20h
;arg_1C          = dword ptr  24h
;
;                push    ebp
;                mov     ebp, esp
;
;                push    ebx
;                push    esi
;                push    edi
;                mov     esi, [ebp+arg_1C]
;                test    esi, esi
;                jz      short @@arg_1C_nz
;                mov     dword ptr [esi], 1
;@@arg_1C_nz:
;                mov     [ebp+arg_1C], 1
;                mov     eax, [ebp+arg_0]
;                mov     [ebp+arg_4], eax
;
;                lea     eax, [ebp+arg_1C]
;                push    eax                   ; arg_18 - arg_1C forward
;                push    [ebp+arg_18]          ; arg_14 - arg_18 forward
;
;                mov     ebx, [ebp+arg_C] ; In_Buf_Size
;                and     ebx, 0FFFFh
;                push    ebx                   ; arg_10 - arg_C forward - DataBuf size
;
;                push    [ebp+arg_10]          ; arg_C - DataBuf
;                push    [ebp+arg_4]           ; arg_8 - COMMAND str
;                call    P2K_SendCommand
;                mov     ecx, _DevList_4
;                mov     word ptr [ecx], 0
;
;                test    eax, eax
;                jz      short @@exit_ok
;                xor     esi, esi
;                jmp     short @@exit
;@@exit_ok:
;                mov     ecx, [ebp+arg_1C]
;                mov     edx, [ebp+arg_14]
;                mov     esi, 1
;                test    cx, cx
;                mov     [edx], cx
;
;@@exit:
;                mov     eax, esi
;                pop     edi
;                pop     esi
;                pop     ebx
;
;                leave
;                retn    20h
;PST_Send_Command endp

;------------- P2K USB IO Procedures ----------------

P2K_SendCommand proc near
arg_0           = dword ptr  8		;command	
arg_4           = dword ptr  0Ch	;string addr
arg_8           = dword ptr  10h	;size
arg_C           = dword ptr  14h	;reply string addr
arg_10          = dword ptr  18h	;reply size

                push    ebp
                mov     ebp, esp

                push    ecx
                push    edx
                push    ebx
                push    esi
                push    edi
                inc     Packet_ID
                cmp     Packet_ID, 1000h
                jb      @@skip_id_fix
                mov     Packet_ID, 0
@@skip_id_fix:
				; clear buffer
                mov     edi, offset packet_buf
                mov     ecx, 400h
                xor     eax, eax
                rep     stosd
                ; branch here !
                cmp isP2k05,0
				;.if isP2k05==0
				jz @@P2K00_SendCommand
				;.else	
					JMP @@P2K05_SendCommand
				;.endif

@@exit:         pop     edi
                pop     esi
                pop     ebx
                pop     edx
                pop     ecx
                leave
                retn    14h
;
; old p2k command
;                
@@P2K00_SendCommand:               
				; prepare buffer, at first setup packet (8byte)
	            mov     edi, offset packet_buf
                mov     byte ptr [edi+00h], 41h
                mov     byte ptr [edi+01h], 02h
                mov     word ptr [edi+02h], 0000h
                mov eax,InterfaceIndex
                mov     word ptr [edi+04h],ax ;8 ; Interface
                mov     dx, Packet_ID
                and     dx, 0FFFh
                xchg    dh, dl
                mov     word ptr [edi+08h], dx ; random - Packet ID
                ;
                ; old p2k , fill buffer with p2k command
                ;
                mov     eax, [ebp+arg_8]
                add     eax, 8
                mov     word ptr [edi+06h], ax    ; all size ws command & size
                mov     edx, [ebp+arg_0]
                and     dx,0FFFh
                xchg    dh,dl
                mov     word ptr [edi+0Ah], dx ; command
                mov     eax, [ebp+arg_8]
                xchg    ah, al
                mov     word ptr [edi+0Ch], ax    ; size
                mov     word ptr [edi+0Eh], 0000h
                mov     eax, [ebp+arg_8]
                add     eax, 12h
                mov     packet_size, eax
                mov     esi, [ebp+arg_4]
                add     edi, 10h
                mov     ecx, [ebp+arg_8]
                rep     movsb
				; buffer ready , send it
                push    offset packet_size
                push    offset packet_buf
;			    DbgDump offset packet_buf,64
;               mov eax,packet_size
                call    USB_WriteData
                cmp     eax, 0
                jz      @@Write_ok

;                push    offset msg_cmd_write_fail
;                call    logstat
                invoke GetMsgAddr,24
                invoke logstat,eax ;addr msg_cmd_write_fail
                mov     eax, -1
                jmp     @@exit

@@Write_ok:
                call    GetTickCount
                mov     ReadStatus_Ticks, eax
@@status_loop:	; get status, clear buffer (12 byte)
                mov     edi, offset status_read_buf
                mov     ecx, 3
                xor     eax, eax
                rep     stosd
				; prepare buffer 
                mov     edi, offset status_read_buf
                mov     byte ptr [edi+00h], 0C1h
                mov     byte ptr [edi+01h], 0
                mov     word ptr [edi+02h], 0
                mov eax,InterfaceIndex
                mov     word ptr [edi+04h], ax ;IF
                mov     word ptr [edi+06h], 8
				; buffer ready , send it
                mov     status_read_size, 0Ch

                push    offset status_read_size
                push    offset status_read_buf
                call    USB_ReadData
                
                cmp     eax, 0
                jnz     @@next_try
                mov     al, status_read_buf+1
                cmp     al, 3 ; got answer, read status info
                jae     @@next_try ; status=not ready
                cmp     al, 0
                jnz     @@done ; status=ready
@@next_try:
                push    1
                call    Sleep

                call    GetTickCount
                sub     eax, ReadStatus_Ticks
                cmp     eax, 9C40h ; timeout
                jb      @@status_loop

                invoke GetMsgAddr,25
                push    eax ;offset msg_cmd_timeout
                invoke logstat,eax
                mov     eax,-1
                jmp     @@exit

@@done:			; status=ready , will read answer
                push    1
                call    Sleep
				; clear buffer
                mov     edi, offset data_read_buf
                mov     ecx, 400h
                xor     eax, eax
                rep     stosd
				; prepare buffer
                mov     edi, offset data_read_buf
                mov     byte ptr [edi+00h], 0C1h
                mov     byte ptr [edi+01h], 1
                movzx   ax, byte ptr status_read_buf+1
                mov     word ptr [edi+02h], ax ; packets #
                mov ecx,InterfaceIndex
                mov     word ptr [edi+04h],cx ;8 ; IF  

                shl     ax, 1
                mov     cx, word ptr status_read_buf+2
                xchg    ch, cl
                add     ax, cx
;                add     ax, word ptr status_read_buf+4
;                add     ax, word ptr status_read_buf+6
                add     ax, 4
                mov     word ptr [edi+06h], ax ; Size
				; buffer ready , send it
                mov     data_read_size, 0FA4h
                push    offset data_read_size
                push    offset data_read_buf
                call    USB_ReadData
                cmp     eax, 0
                jz      @@Read_ok

;                push    offset msg_cmd_read_fail
;                call    logstat
                invoke GetMsgAddr,24
                invoke logstat,eax ;addr msg_cmd_write_fail
                mov     eax, -1
                jmp     @@exit
@@Read_ok:
				.if isVerboseLog==1
					invoke HexAnswer,offset data_read_buf,hexsize
				.endif
;				.if isVerboseLog==1
;					pusha
;					mov ecx,36
;					mov esi,offset data_read_buf ;buf addr
;					shr ecx,2  ;/4
;					mov edi,offset str_buf
;@@uc1loop:			mov eax,[esi]
;					xchg al,ah
;					rol eax,16
;					xchg al,ah
;					pusha	
;					invoke dw2ah,eax,edi
;					popa
;					add edi,8
;					add esi,4
;					loop @@uc1loop
;					invoke logstat,addr str_buf
;					invoke logstat,addr crlfsep
;					popa
;				.endif

                mov     esi, offset data_read_buf
                cmp     byte ptr [esi+00h], 1
                jnz     @@fail
                mov     cx, [esi+04h]
                xchg    ch,cl
                mov     dl, [esi+06h]
                and     dl, 80h
                cmp     dl, 80h
                jnz     @@fail
                mov     dx, [esi+06h]
                xchg    dh, dl
                and     dx, 0FFFh ; Packet ID
                cmp     Packet_ID, dx
                jnz     @@fail
                mov     dl, [esi+08h]
                shr     dl, 4

                cmp     dl, 6        ; Answ 6 - result ok, no data returned
                mov     eax, 0
                jz      @@exit

                cmp     dl, 8        ; Answ 8 - result ok
                jz      @@op_ok
                and     edx, 0Fh
                ;;mov     eax, [IO_Err+edx*4]
                invoke GetMsgAddr,edx ;eax
;                push    eax
;                call    logstat
                invoke logstat,eax
                mov     eax, -1
                jmp     @@exit
@@op_ok:
                mov     dx, [esi+0Ah]
                xchg    dh, dl
                sub     cx, 8
                cmp     cx, dx
                jnz     @@fail ; bad packet - size mismatch
                jmp     @@ok

@@fail:
;                push    offset msg_cmd_answer_fail
;                call    logstat
                invoke GetMsgAddr,26
                invoke logstat,eax ;addr msg_cmd_answer_fail
                mov     eax, 1
                jmp     @@exit

@@ok:			; copy data to out buffer
                add     esi, 0Eh
                mov     edi, [ebp+arg_C]
                mov     eax, [ebp+arg_10]
                and     ecx, 0FFFFh
                mov     [eax], ecx
                rep     movsb
                mov     eax, 0
                jmp @@exit
;
; new p2k05 command
;                
@@P2K05_SendCommand:
				; prepare buffer, no setup packet at all !
	            mov     edi, offset packet_buf
                mov     byte ptr [edi+00h], 2 ; p2k05 bulk mode
                mov     eax, [ebp+arg_8] ; get size
                add eax,12
                mov     dword ptr [edi+01h], eax ; allsize
                mov     dx, Packet_ID
                and     dx, 0FFFh
                xchg    dh, dl
                mov     word ptr [edi+05h], dx ; random - Packet ID
                mov     edx, [ebp+arg_0]
                and     dx,0FFFh
                xchg    dh,dl
                mov     word ptr [edi+07h], dx ; command
                mov     eax, [ebp+arg_8]
                xchg    ah, al
                mov     word ptr [edi+09h],0
                mov     word ptr [edi+0bh],0
                mov     word ptr [edi+0dh],0
                mov     word ptr [edi+0fh], ax    ; size
                mov     eax, [ebp+arg_8]
                add     eax, 12+6
                mov     packet_size, eax
                mov     esi, [ebp+arg_4]
                add     edi, 11h
                mov     ecx, [ebp+arg_8]
                rep     movsb
				; buffer ready, send it
				;******************************************************
				; Branch here: traditional p2k05 or p2k05 over USBLAN *
				;******************************************************
				cmp isUSBLAN,3
 				jz @@P2K05OUSBLAN_SendCommand
 
                push    offset packet_size
                push    offset packet_buf
;			    DbgDump offset packet_buf,64
;               mov eax,packet_size
                call    USB_WriteDataBulk
                cmp     eax, 0
                jz      @@Write_ok05

;                push    offset msg_cmd_write_fail
;                call    logstat
                invoke GetMsgAddr,24
                invoke logstat,eax ;addr msg_cmd_write_fail
                mov     eax, -1
                jmp     @@exit

@@Write_ok05:
                call    GetTickCount
                mov     ReadStatus_Ticks, eax
@@status_loop05:
                mov     edi, offset status_read_buf
                mov     ecx, 3
                xor     eax, eax
                rep     stosd
				; prepare buffer
                mov     edi, offset status_read_buf
                mov     byte ptr [edi+00h], 2
                mov     byte ptr [edi+01h], 0
                mov     byte ptr [edi+02h], 10h
                mov     byte ptr [edi+03h], 0
                mov     byte ptr [edi+04h], 0

                mov     status_read_size, 5

                push    offset status_read_size
                push    offset status_read_buf
                call    USB_ReadDataBulk
                
                ;mov eax,status_read_size
			    ;DbgDump offset status_read_buf,64
                
                cmp     eax, 0
                jnz     @@next_try05
                mov     al, status_read_buf
                cmp     al, 82h
                jz     @@done05
                cmp     al, 80h
                jz     @@done05
                jmp @@fail05
;                jae     @@next_try05
;                cmp     al, 2
;                jnz     @@done05
                ;jmp     @@done05
@@next_try05:
                push    1
                call    Sleep

                call    GetTickCount
                sub     eax, ReadStatus_Ticks
                cmp     eax, 1388h ;9C40h ; timeout
                jb      @@status_loop05

                invoke GetMsgAddr,25
                push    eax ;offset msg_cmd_timeout
                invoke logstat,eax
                mov     eax,-1
                jmp     @@exit

@@done05:
				
;                push    1
;                call    Sleep
;
;                mov     edi, offset data_read_buf
;                mov     ecx, 400h
;                xor     eax, eax
;                rep     stosd
;
;                mov     edi, offset data_read_buf
;                mov     byte ptr [edi+00h], 2
;                mov     byte ptr [edi+01h], 0
;                mov     byte ptr [edi+02h], 10h
;                mov     byte ptr [edi+03h], 0
;                mov     byte ptr [edi+04h], 0
;
;                shl     ax, 1
;                mov     cx, word ptr status_read_buf+2
;                xchg    ch, cl
;                add     ax, cx
;;                add     ax, word ptr status_read_buf+4
;;                add     ax, word ptr status_read_buf+6
;                add     ax, 4
;                mov     word ptr [edi+06h], ax ; Size
;
;                mov     data_read_size, 0FA4h
;                push    offset data_read_size
;                push    offset data_read_buf
;                call    USB_ReadDataBulk
;                cmp     eax, 0
;                jz      @@Read_ok05
;
;;                push    offset msg_cmd_read_fail
;;                call    logstat
;                invoke GetMsgAddr,24
;                invoke logstat,eax ;addr msg_cmd_write_fail
;                mov     eax, -1
;                jmp     @@exit
@@Read_ok05:
				.if isVerboseLog==1
					invoke HexAnswer,offset status_read_buf,hexsize
				.endif
;				.if isVerboseLog==1
;					pusha
;					mov ecx,36
;					mov esi,offset status_read_buf ;data_read_buf ;buf addr
;					shr ecx,2  ;/4
;					mov edi,offset str_buf
;@@uc1loop05:			mov eax,[esi]
;					xchg al,ah
;					rol eax,16
;					xchg al,ah
;					pusha	
;					invoke dw2ah,eax,edi
;					popa
;					add edi,8
;					add esi,4
;					loop @@uc1loop05
;					invoke logstat,addr str_buf
;					invoke logstat,addr crlfsep
;					popa
;				.endif


			    ;DbgDump offset status_read_buf,64

                mov     esi, offset status_read_buf ;data_read_buf
;                cmp     byte ptr [esi+00h], 1
;                jnz     @@fail05
;                mov     cx, [esi+04h]
;                xchg    ch,cl
;                mov     dl, [esi+06h]
;                and     dl, 80h
;                cmp     dl, 80h
;                jnz     @@fail05
;                mov     dx, [esi+06h]
;                xchg    dh, dl
;                and     dx, 0FFFh ; Packet ID
;                cmp     Packet_ID, dx
;                jnz     @@fail05
;                mov     dl, [esi+08h]
;                shr     dl, 4
;
;                cmp     dl, 6        ; Answ 6 - result ok, no data returned
;                mov     eax, 0
;                jz      @@exit
;
;                cmp     dl, 8        ; Answ 8 - result ok
;                jz      @@op_ok05
;                and     edx, 0Fh
;                ;;mov     eax, [IO_Err+edx*4]
;                invoke GetMsgAddr,edx ;eax
;;                push    eax
;;                call    logstat
;                invoke logstat,eax
;                mov     eax, -1
;                jmp     @@exit
@@op_ok05:
                mov     dx, [esi+0Ah]
                xchg    dh, dl
                mov cx,dx
;                sub     cx, 8
;                cmp     cx, dx
;                jnz     @@fail05 ; bad packet - size mismatch
                jmp     @@ok05

@@fail05:
;                push    offset msg_cmd_answer_fail
;                call    logstat
                invoke GetMsgAddr,26
                invoke logstat,eax ;addr msg_cmd_answer_fail
                mov     eax, 1
                jmp     @@exit

@@ok05:
                add     esi, 0ch
                mov     edi, [ebp+arg_C]
                mov     eax, [ebp+arg_10]
                and     ecx, 0FFFFh
                mov     [eax], ecx
                rep     movsb
                mov     eax, 0
                jmp @@exit
;
; New TCP/IP Socket functions
;                
@@P2K05OUSBLAN_SendCommand:
				
				;mov eax,packet_size
				;DbgDump offset packet_buf,eax
				mov esi,packet_size
				sub esi,6
				push esi
				.if byte ptr packet_buf+8==04ah
					mov byte ptr packet_buf+18,1
				.endif	
				.if isVerboseLog==1
					invoke logstat,StrAddr("Send p2k command over USBLAN.")
					invoke HexAnswer,offset packet_buf+5,esi
				.endif
				;
				; send data ( maybe, will loop here, if not all bytes sent ) ( return vaule is sent byte )
				; 
				pop edi
				push edi
				invoke send,hSocket,addr packet_buf+5,edi,0
				pop edi
				.if eax!=edi
					invoke logstat,StrAddr("Send error!")
				.endif
				;
				; receive answer ( maybe, will loop here, if not all bytes received ) ( until return value will be zero )
				; 
				invoke recv, hSocket, addr seem_data2, 2000, 0
				.if isVerboseLog==1
					invoke HexAnswer,offset seem_data2,eax
				.endif
				;
				; check answer status
				;
				mov 	esi,offset seem_data2
				cmp byte ptr [esi],80h
				jz @@okou
				cmp byte ptr [esi],82h
				jz @@okou
@@nokou:		mov eax,1
				jmp @@exit
				;
				; copy answer to output buffer
				;
@@okou:         mov     dx, [esi+0Ah]
                xchg    dh, dl
                mov cx,dx

                add     esi, 0ch
                mov     edi, [ebp+arg_C]
                mov     eax, [ebp+arg_10]
                and     ecx, 0FFFFh
                cmp isUSBLAN,3
                jz @@okou2
                cmp 	ecx,0
                jz		@@nokou
@@okou2:        mov     [eax], ecx
                rep     movsb
                mov     eax, 0
                jmp @@exit


P2K_SendCommand endp

USB_WriteData   proc    near ;uses ecx edi esi

arg_0           = dword ptr  8		; buf addr	
arg_4           = dword ptr  0Ch	; addr of size var

                push    ebp
                mov     ebp, esp

				.if isVerboseLog==1
					mov esi,[ebp+arg_4] ;size
					mov ecx,[esi]
					invoke HexAnswer,[ebp+arg_0],ecx
				.endif
;				.if isVerboseLog==1
;					mov esi,[ebp+arg_4] ;size
;					mov ecx,[esi]
;					mov esi,[ebp+arg_0] ;buf addr
;					shr ecx,2  ;/4
;					mov edi,offset str_buf
;@@uwloop:			mov eax,[esi]
;					xchg al,ah
;					rol eax,16
;					xchg al,ah
;					pusha	
;					invoke dw2ah,eax,edi
;					popa
;					add edi,8
;					add esi,4
;					loop @@uwloop
;					invoke logstat,addr str_buf
;				.endif	
				
                push    0
                push    0
                push    1
                push    0
                call    CreateEventA
                cmp     eax, 0
                jnz     @@event_ok

;                push    offset msg_usb_event_fail
;                call    logstat
                invoke GetMsgAddr,28
                invoke logstat,eax ;addr msg_usb_event_fail
                mov     eax, -1
                jmp     @@exit
@@event_ok:
                mov     DevIO_Event, eax

                push    DevIO_Event
                call    ResetEvent
                cmp     eax, 0
                jnz     @@reset_ok

                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_reset_fail
;                call    logstat
                invoke GetMsgAddr,29
                invoke logstat,eax ;addr msg_usb_reset_fail
                mov     eax, -1
                jmp     @@exit
@@reset_ok:

                push    offset DevIO_Overlapped
                push    0
                push    5
                push    offset DevIO_Result
                mov     eax,[ebp+arg_4] ; InBuf_Size
                mov     eax, [eax]
                push    eax
                push    [ebp+arg_0]     ; InBuf
                mov eax,80002014h
                push eax
                ;push    80002014h
                push    _DevIF
                call    DeviceIoControl

                push    P2k_Timeout ;1388h ;3E8h 
                push    DevIO_Event
                call    WaitForSingleObject
                cmp     eax, 0
                jz      @@wait_ok

                push    _DevIF
                call    CancelIo
                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_wait_fail
;                call    logstat
                invoke GetMsgAddr,30
                invoke logstat,eax ;addr msg_usb_wait_fail
                mov     eax, -1
                jmp     @@exit
@@wait_ok:
				.if isVerboseLog==1
	                invoke GetMsgAddr,104
	                invoke logstat,eax ;ok
	                invoke logstat,addr crlfsep
	            .endif    
                push    0
                push    [ebp+arg_4] ; InBuf_Size - recvd
                push    offset DevIO_Overlapped
                push    _DevIF
                call    GetOverlappedResult
                cmp     eax, 0
                jnz     @@devio_ok

                push    _DevIF
                call    CancelIo
                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_result_fail
;                call    logstat
                invoke GetMsgAddr,31
                invoke logstat,eax ;addr msg_usb_result_fail
                mov     eax, -1
                jmp     @@exit

@@devio_ok:
                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_write_ok
;                call    logstat
                mov     eax, 0
@@exit:
                leave
                retn    8
USB_WriteData   endp
USB_WriteDataBulk proc    near

arg_0           = dword ptr  8		; send buf addr
arg_4           = dword ptr  0Ch	; addr of raw size buf
;arg_0           = dword ptr  8		; device handle
;arg_4           = dword ptr  0Ch	; send buf addr
;arg_8           = dword ptr  10h	; addr of raw size buf
;arg_C           = dword ptr  14h	; type variable 4:p2k, 2:p2k05
;arg_10          = dword ptr  18h	; timeout

                push    ebp
                mov     ebp, esp
                push    ecx
                push    edx
                push    ebx
                push    esi
                push    edi

				.if isVerboseLog==1
					mov esi,[ebp+arg_4] ;size
					mov ecx,[esi]
					invoke HexAnswer,[ebp+arg_0],ecx
				.endif
;				.if isVerboseLog==1
;					mov esi,[ebp+arg_4] ;size
;					mov ecx,[esi]
;					mov esi,[ebp+arg_0] ;buf addr
;					shr ecx,2  ;/4
;					inc ecx
;					mov edi,offset str_buf
;@@uwloop:			mov eax,[esi]
;					xchg al,ah
;					rol eax,16
;					xchg al,ah
;					pusha	
;					invoke dw2ah,eax,edi
;					popa
;					add edi,8
;					add esi,4
;					loop @@uwloop
;					invoke logstat,addr str_buf
;				.endif	

                push    0
                push    0
                push    1
                push    0
                call    CreateEventA
                cmp     eax, 0
                jnz     @@event_ok

;                push    offset msg_usb_event_fail
;                call    logstat
                invoke GetMsgAddr,28
                invoke logstat,eax ;addr msg_usb_event_fail
                mov     eax, -1
                jmp     @@exit
@@event_ok:
                mov     DevIO_Event, eax

                push    DevIO_Event
                call    ResetEvent
                cmp     eax, 0
                jnz     @@reset_ok

                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_reset_fail
;                call    logstat
                invoke GetMsgAddr,29
                invoke logstat,eax ;addr msg_usb_reset_fail
                mov     eax, -1
                jmp     @@exit
@@reset_ok:
;                mov     edi, offset packet_buf
;                mov     esi, [ebp+arg_4]
;                mov     al, byte ptr [ebp+arg_C]
;                stosb
;                mov     eax,[ebp+arg_8] ; InBuf_Size
;                mov     eax, [eax]
;                push eax
;                stosd
;                mov     ecx, eax
;                rep     movsb
;                pop eax
                push    offset DevIO_Overlapped
                push    0
                push    0
                push    0
                ;add     eax, 6
                ;push    eax
                mov     eax,[ebp+arg_4] ; InBuf_Size
                mov     eax, [eax]
                push    eax
                push    [ebp+arg_0] ; offset packet_buf ; [ebp+arg_4]     ; InBuf
                push    80002018h
                push    _DevIF ;[ebp+arg_0]

			;	DbgDump [ebp+arg_0],32

                call    DeviceIoControl

                push    P2k05_Timeout ;1388h ;[ebp+arg_10] ; timeout 
                push    DevIO_Event
                call    WaitForSingleObject
                cmp     eax, 0
                jz      @@wait_ok

                push    _DevIF ;[ebp+arg_0]
                call    CancelIo
                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_wait_fail
;                call    logstat
                invoke GetMsgAddr,30
                invoke logstat,eax ;addr msg_usb_wait_fail
                mov     eax, -1
                jmp     @@exit
@@wait_ok:
				.if isVerboseLog==1
	                invoke GetMsgAddr,104
	                invoke logstat,eax ;ok
	                invoke logstat,addr crlfsep
	            .endif    
                push    0
                push    [ebp+arg_4] ; InBuf_Size - recvd
                push    offset DevIO_Overlapped
                push    _DevIF ;[ebp+arg_0]
                call    GetOverlappedResult
                cmp     eax, 0
                jnz     @@devio_ok

                push    _DevIF ;[ebp+arg_0]
                call    CancelIo
                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_result_fail
;                call    logstat
                invoke GetMsgAddr,31
                invoke logstat,eax ;addr msg_usb_result_fail
                mov     eax, -1
                jmp     @@exit

@@devio_ok:
                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_write_ok
;                call    logstat
                mov     eax, 0
@@exit:
                pop     edi
                pop     esi
                pop     ebx
                pop     edx
                pop     ecx
                leave
                retn    8 ;14h
USB_WriteDataBulk endp

USB_ReadData    proc    near ;uses edi ecx esi 

arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp

				.if isVerboseLog==1
					mov ecx,24
					mov esi,[ebp+arg_0] ;buf addr
					shr ecx,2  ;/4
					mov edi,offset str_buf
@@urwloop:			mov eax,[esi]
					xchg al,ah
					rol eax,16
					xchg al,ah
					pusha	
					invoke dw2ah,eax,edi
					popa
					add edi,8
					add esi,4
					loop @@urwloop
					invoke logstat,addr str_buf
				.endif	
				
                push    0
                push    0
                push    1
                push    0
                call    CreateEventA
                cmp     eax, 0
                jnz     @@event_ok

;                push    offset msg_usb_event_fail
;                call    logstat
                invoke GetMsgAddr,28
                invoke logstat,eax ;addr msg_usb_event_fail
                mov     eax, -1
                jmp     @@exit
@@event_ok:
                mov     DevIO_Event, eax

                push    DevIO_Event
                call    ResetEvent
                cmp     eax, 0
                jnz     @@reset_ok

                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_reset_fail
;                call    logstat
                invoke GetMsgAddr,29
                invoke logstat,eax ;addr msg_usb_reset_fail
                mov     eax, -1
                jmp     @@exit
@@reset_ok:

                push    offset DevIO_Overlapped
                push    0
                push    1005h
                push    offset DevIO_Result
                mov     eax,[ebp+arg_4] ; InBuf_Size
                push    9
                push    [ebp+arg_0]     ; InBuf
                mov eax,80002014h
                push eax
                ;push    80002014h
                push    _DevIF
                call    DeviceIoControl

                push    9C40h
                push    DevIO_Event
                call    WaitForSingleObject
                cmp     eax, 0
                jz      @@wait_ok

                push    _DevIF
                call    CancelIo
                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_wait_fail
;                call    logstat
                invoke GetMsgAddr,30
                invoke logstat,eax ;addr msg_usb_wait_fail
                mov     eax, -1
                jmp     @@exit
@@wait_ok:
				.if isVerboseLog==1
	                invoke GetMsgAddr,105
    	            invoke logstat,eax ;ok
    	        .endif    
                push    0
                push    [ebp+arg_4] ; InBuf_Size - will receive size here
                push    offset DevIO_Overlapped
                push    _DevIF
                call    GetOverlappedResult
                cmp     eax, 0
                jnz     @@devio_ok

                push    _DevIF
                call    CancelIo
                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_result_fail
;                call    logstat
                invoke GetMsgAddr,31
                invoke logstat,eax ;addr msg_usb_result_fail
                mov     eax, -1
                jmp     @@exit
@@devio_ok:
                mov     esi, [ebp+arg_4]
                mov     ecx, [esi]
                cmp     ecx, 4
                jnb     @@size_ok
                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_size_fail
;                call    logstat
                invoke GetMsgAddr,32
                invoke logstat,eax ;addr msg_usb_size_fail
                mov     eax, -1
                jmp     @@exit
@@size_ok:
                sub     ecx, 4
                mov     [esi], ecx ;size-4
                mov     esi, offset DevIO_Result
                add     esi, 4
                mov     edi, [ebp+arg_0]
                rep     movsb
                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_read_ok
;                call    logstat
                mov     eax, 0
@@exit:
                leave
                retn    8
USB_ReadData    endp
USB_ReadDataBulk  proc    near ;uses edi ecx

arg_0           = dword ptr  8 		; addr of buffer
arg_4           = dword ptr  0Ch 	; addr of size var
;arg_8           = dword ptr  10h
;arg_C           = dword ptr  14h
;arg_10          = dword ptr  18h

                push    ebp
                mov     ebp, esp
                push    esi

				.if isVerboseLog==1
					mov ecx,24
					mov esi,[ebp+arg_0] ;buf addr
					shr ecx,2  ;/4
					mov edi,offset str_buf
@@urwloop:			mov eax,[esi]
					xchg al,ah
					rol eax,16
					xchg al,ah
					pusha	
					invoke dw2ah,eax,edi
					popa
					add edi,8
					add esi,4
					loop @@urwloop
					invoke logstat,addr str_buf
				.endif	
				
                push    0
                push    0
                push    1
                push    0
                call    CreateEventA
                cmp     eax, 0
                jnz     @@event_ok

;                push    offset msg_usb_event_fail

;                call    logstat
                invoke GetMsgAddr,28
                invoke logstat,eax ;addr msg_usb_event_fail
                mov     eax, -1
                jmp     @@exit
@@event_ok:
                mov     DevIO_Event, eax

                push    DevIO_Event
                call    ResetEvent
                cmp     eax, 0
                jnz     @@reset_ok

                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_reset_fail
;                call    logstat
                invoke GetMsgAddr,29
                invoke logstat,eax ;addr msg_usb_reset_fail
                mov     eax, -1
                jmp     @@exit
@@reset_ok:

;                mov     edi, offset packet_buf
;                mov     al, byte ptr [ebp+arg_C]
;                stosb
;                mov     eax, [ebp+arg_8]
;                mov     eax, [eax]
;                stosd

                push    offset DevIO_Overlapped
                push    0
                push    1005h
                push    offset DevIO_Result
                push    5
                push    [ebp+arg_0]     ; InBuf
                push    8000201Ch
                push    _DevIF ;[ebp+arg_0]
                call    DeviceIoControl

                push    9c40h ;[ebp+arg_10] ; timeout
                push    DevIO_Event
                call    WaitForSingleObject
                cmp     eax, 0
                jz      @@wait_ok

                push    _DevIF ;[ebp+arg_0]
                call    CancelIo
                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_wait_fail
;                call    logstat
                invoke GetMsgAddr,30
                invoke logstat,eax ;addr msg_usb_wait_fail
                mov     eax, -1
                jmp     @@exit
@@wait_ok:
				.if isVerboseLog==1
	                invoke GetMsgAddr,105
    	            invoke logstat,eax ;ok
    	        .endif    

                push    0
                push    [ebp+arg_4] ; InBuf_Size - will receive size here
                push    offset DevIO_Overlapped
                push    _DevIF ;[ebp+arg_0]
                call    GetOverlappedResult
                cmp     eax, 0
                jnz     @@devio_ok

                push    _DevIF ;[ebp+arg_0]
                call    CancelIo
                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_result_fail
;                call    logstat
                invoke GetMsgAddr,31
                invoke logstat,eax ;addr msg_usb_result_fail
                mov     eax, -1
                jmp     @@exit
@@devio_ok:
                mov     esi, [ebp+arg_4] ; received size
                mov     ecx, [esi]
                cmp     ecx, 4
                jnb     @@size_ok
                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_size_fail
;                call    logstat
                invoke GetMsgAddr,32
                invoke logstat,eax ;addr msg_usb_size_fail
                mov     eax, -1
                jmp     @@exit
@@size_ok:
                sub     ecx, 4
                mov     [esi], ecx ;size-4
                mov     hexsize,ecx
                mov     esi, offset DevIO_Result
                add     esi, 4
                mov     edi, [ebp+arg_0]
                rep     movsb
                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_read_ok
;                call    logstat
                mov     eax, 0
@@exit:
                pop     esi
                leave
                retn    8h ;14h
USB_ReadDataBulk  endp

USB_GetIFInfo   proc    near

arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp

                push    ecx
                push    esi
                push    edi

                push    0
                push    0
                push    1
                push    0
                call    CreateEventA
                cmp     eax, 0
                jnz     @@event_ok

;                push    offset msg_usb_event_fail
;                call    logstat
                invoke GetMsgAddr,28
                invoke logstat,eax ;addr msg_usb_event_fail
                mov     eax, -1
                jmp     @@exit
@@event_ok:
                mov     DevIO_Event, eax

                push    DevIO_Event
                call    ResetEvent
                cmp     eax, 0
                jnz     @@reset_ok


                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_reset_fail
;                call    logstat
                invoke GetMsgAddr,29
                invoke logstat,eax ;addr msg_usb_reset_fail
                mov     eax, -1
                jmp     @@exit
@@reset_ok:
                mov     eax, [ebp+arg_0]
                mov     IF_Info_cmd, eax

                push    offset DevIO_Overlapped
                push    offset IF_Info_recvd
                push    105h
                push    [ebp+arg_4] 
                push    2					; command lenght
                push    offset IF_Info_cmd  ; InBuf command (2)
                push    80002010h
                push    _DevIF
                call    DeviceIoControl

                push    1388h
                push    DevIO_Event
                call    WaitForSingleObject
                cmp     eax, 0
                jz      @@wait_ok

                push    _DevIF
                call    CancelIo
                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_wait_fail
;                call    logstat
                invoke GetMsgAddr,30
                invoke logstat,eax ;addr msg_usb_wait_fail
                mov     eax, -1
                jmp     @@exit
@@wait_ok:

                push    0
                push    offset IF_Info_recvd ; InBuf_Size - recvd
                push    offset DevIO_Overlapped
                push    _DevIF
                call    GetOverlappedResult
                cmp     eax, 0
                jnz     @@devio_ok

                push    _DevIF
                call    CancelIo
                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_result_fail
;                call    logstat
                invoke GetMsgAddr,31
                invoke logstat,eax ;addr msg_usb_result_fail
                mov     eax, -1
                jmp     @@exit
@@devio_ok:
                cmp     IF_Info_recvd, 4
                jnb     @@size_ok
                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_size_fail
;                call    logstat
                invoke GetMsgAddr,32
                invoke logstat,eax ;addr msg_usb_size_fail
                mov     eax, -1
                jmp     @@exit
@@size_ok:
                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_read_ok
;                call    logstat
                mov     ecx, dword ptr str_buf   ; [ebp+arg_4] answer buffer
                mov     esi, offset str_buf+4	 ; that str_buf is coming from caller (FindUSBClass)
                mov     edi, offset str_buf
@@str_loop:
                lodsw
                stosb
                loop    @@str_loop

                mov     eax, 0
@@exit:
                pop     edi
                pop     esi
                pop     ecx
                leave
                retn    8
USB_GetIFInfo   endp

USB_Test   proc    near

arg_0           = dword ptr  8		;cmd 	
arg_4           = dword ptr  0Ch	;cmd len
arg_8           = dword ptr  10h	;ans
arg_c           = dword ptr  14h	;ioctl

                push    ebp
                mov     ebp, esp

                push    ecx
                push    esi
                push    edi

                mov eax,[ebp+arg_0]		
                mov ebx,[ebp+arg_4]		
                mov ecx,[ebp+arg_8]
				;DbgDump eax,16
				;DbgDump ecx,16
                		
                push    0
                push    0
                push    1
                push    0
                call    CreateEventA
                cmp     eax, 0
                jnz     @@event_ok

;                push    offset msg_usb_event_fail
;                call    logstat
                invoke GetMsgAddr,28
                invoke logstat,eax ;addr msg_usb_event_fail
                mov     eax, -1
                jmp     @@exit
@@event_ok:
                mov     DevIO_Event, eax

                push    DevIO_Event
                call    ResetEvent
                cmp     eax, 0
                jnz     @@reset_ok

                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_reset_fail
;                call    logstat
                invoke GetMsgAddr,29
                invoke logstat,eax ;addr msg_usb_reset_fail
                mov     eax, -1
                jmp     @@exit
@@reset_ok:
				; prepare command buffer
                mov     eax, [ebp+arg_0]
                mov     IF_Info_cmd, eax

                push    offset DevIO_Overlapped
                push    offset IF_Info_recvd
                push    1005h
                push    [ebp+arg_8] 
                push    [ebp+arg_4]		; command lenght
                push    [ebp+arg_0]     ; IF_Info_cmd  ; InBuf command (2)
                push    [ebp+arg_c] ;80002010h
                push    _DevIF
                
;                mov eax,[ebp+arg_4]
;                mov ebx,[ebp+arg_c]
;                mov esi,[ebp+arg_0]
;				DbgDump esi,32
                
                
                call    DeviceIoControl

                push    1388h
                push    DevIO_Event
                call    WaitForSingleObject
                cmp     eax, 0
                jz      @@wait_ok

                push    _DevIF
                call    CancelIo
                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_wait_fail
;                call    logstat
                invoke GetMsgAddr,30
                invoke logstat,eax ;addr msg_usb_wait_fail
                mov     eax, -1
                jmp     @@exit
@@wait_ok:

                push    0
                push    offset IF_Info_recvd ; InBuf_Size - recvd
                push    offset DevIO_Overlapped
                push    _DevIF
                call    GetOverlappedResult
                cmp     eax, 0
                jnz     @@devio_ok

                push    _DevIF
                call    CancelIo
                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_result_fail
;                call    logstat
                invoke GetMsgAddr,31
                invoke logstat,eax ;addr msg_usb_result_fail
                mov     eax, -1
                jmp     @@exit
@@devio_ok:
                cmp     IF_Info_recvd, 4
                jnb     @@size_ok
                push    DevIO_Event
                call    CloseHandle
;                push    offset msg_usb_size_fail
;                call    logstat
                invoke GetMsgAddr,32
                invoke logstat,eax ;addr msg_usb_size_fail
                mov     eax, -1
                jmp     @@exit
@@size_ok:
                push    DevIO_Event
                call    CloseHandle
 ;                push    offset msg_usb_read_ok
 ;                call    logstat
;                mov     ecx, dword ptr str_buf   ; [ebp+arg_4] answer buffer
;                mov     esi, offset str_buf+4	 ; that str_buf is coming from caller (FindUSBClass)
;                mov     edi, offset str_buf
;@@str_loop:
;                lodsw
;                stosb
;                loop    @@str_loop

                mov     eax, 0
@@exit:
                pop     edi
                pop     esi
                pop     ecx
                leave
                retn    10h
USB_Test	   endp

;------------- Phone initialize procs ----------------
COM_Find	    proc near
                push    ebp
                mov     ebp, esp
                push    edi
                push    ecx

                mov     edi, offset keyval_buf
                mov     ecx, 40h
                xor     eax, eax
                rep     stosd

                push    offset Key_handle
                push    20019h
                push    0
                push    offset str_serialcom_key
                push    80000002h
                call    RegOpenKeyExA

                mov     keyval_size, 100h

                push    offset keyval_size
                push    offset keyval_buf
                push    offset keyval_type
                push    0
                push    offset str_usbser
                push    Key_handle
                call    RegQueryValueExA

                push    Key_handle
                call    RegCloseKey
                mov     eax, dword ptr keyval_buf
                and     eax, 00FFFFFFh
                cmp     eax, 'MOC'
                jnz     @@fail
                mov     eax, 0
                jmp     @@exit
@@fail:
                mov     eax, -1
@@exit:
                pop     ecx
                pop     edi
                leave
                retn
COM_Find        endp
COM_Find_New    proc near
                push    ebp
                mov     ebp, esp
                push    edi
                push    ecx

                mov     edi, offset keyval_buf
                mov     ecx, 40h
                xor     eax, eax
                rep     stosd

                push    offset Key_handle
                push    20019h
                push    0
                push    offset str_serialcom_key2
                push    80000002h
                call    RegOpenKeyExA
				
				mov Comindex,-1
Comloop:		inc Comindex
	    		mov     keyval_size, 100
	    		mov     keyval_size2, 100
				invoke RegEnumValue,Key_handle,Comindex,addr bufferx,addr keyval_size,0,addr keyval_type,addr keyval_buf,addr keyval_size2
				cmp eax,ERROR_NO_MORE_ITEMS
				jz Comloopend
				mov edi,offset bufferx
				add edi,8
				mov byte ptr [edi+7],0
				;DbgDump esi,32
				;DbgDump offset str_usbser2,32
				;DbgDump offset keyval_buf,32
				invoke lstrcmp,edi,addr str_usbser2 ; USBPDO- ?
				jnz Comloop
				; found
				
;				DbgDump offset bufferx,32
;				DbgDump offset keyval_buf,32

;                mov     keyval_size, 100h
;                push    offset keyval_size
;                push    offset keyval_buf
;                push    offset keyval_type
;                push    0
;                push    offset str_usbser2
;                push    Key_handle
;                call    RegQueryValueExA

                push    Key_handle
                call    RegCloseKey
                mov     eax, dword ptr keyval_buf
                and     eax, 00FFFFFFh
                cmp     eax, 'MOC'
                jnz     @@fail
                mov     eax, 0
                jmp     @@exit
	; not found
Comloopend:
                push    Key_handle
                call    RegCloseKey
                
@@fail:
                mov     eax, -1
@@exit:
                pop     ecx
                pop     edi
                leave
                retn
COM_Find_New    endp
COM_Find_New2    proc near
                push    ebp
                mov     ebp, esp
                push    edi
                push    ecx

                mov     edi, offset keyval_buf
                mov     ecx, 40h
                xor     eax, eax
                rep     stosd

                push    offset Key_handle
                push    20019h
                push    0
                push    offset str_serialcom_key2
                push    80000002h
                call    RegOpenKeyExA
				cmp eax,0 ;error!
				jnz @@fail	
				mov Comindex,-1
Comloop:		inc Comindex
	    		mov     keyval_size, 100
	    		mov     keyval_size2, 100
				invoke RegEnumValue,Key_handle,Comindex,addr bufferx,addr keyval_size,0,addr keyval_type,addr keyval_buf,addr keyval_size2
				cmp eax,ERROR_NO_MORE_ITEMS
				jz Comloopend
				mov edi,offset bufferx
				add edi,8
				mov byte ptr [edi+4],0
				;DbgDump esi,32
				;DbgDump offset str_usbser2,32
				;DbgDump offset keyval_buf,32
				invoke lstrcmp,edi,addr str_usbser3 ; USBPDO- ?
				;DbgDump edi,16
				jnz Comloop
				; found
				
;				DbgDump offset bufferx,32
;				DbgDump offset keyval_buf,32

;                mov     keyval_size, 100h
;                push    offset keyval_size
;                push    offset keyval_buf
;                push    offset keyval_type
;                push    0
;                push    offset str_usbser2
;                push    Key_handle
;                call    RegQueryValueExA

                push    Key_handle
                call    RegCloseKey
                mov     eax, dword ptr keyval_buf
                and     eax, 00FFFFFFh
                cmp     eax, 'MOC'
                jnz     @@fail
                mov isCDMA05,1
                mov     eax, 0
                jmp     @@exit
	; not found
Comloopend:
                push    Key_handle
                call    RegCloseKey
                
@@fail:
                mov     eax, -1
@@exit:
                pop     ecx
                pop     edi
                leave
                retn
COM_Find_New2    endp


Switch_mode     proc near
                push    ebp
                mov     ebp, esp
                invoke lstrcpy,addr bufferx,addr at_mode
                invoke lstrcat,addr bufferx,addr arrow
                invoke lstrcat,addr bufferx,addr keyval_buf
				invoke logstat,offset bufferx
				invoke lstrcpy,addr bufferx,StrAddr("\\.\")
				invoke lstrcat,addr bufferx,addr keyval_buf
                push    NULL ;-1
                push    0
                push    OPEN_EXISTING ;1 ; Create new
                push    NULL ;0
                push    0
                push    0C0000000h ; generic RW
                push    offset bufferx ;keyval_buf
                call    CreateFileA
                mov     ComHandle, eax
                cmp     eax,0
                jnz     @@create_ok
                mov     eax, -1
                jmp     @@exit
@@create_ok:
                ;
                ; set COM params
                ;
                invoke GetCommState,ComHandle,addr dcb
                mov dcb.BaudRate,CBR_115200
				mov dcb.ByteSize,8
				mov dcb.Parity,0
				mov dcb.StopBits,0
                invoke SetCommState,ComHandle,addr dcb
                
                push    0
                push    offset at_readed
                push    0Bh
                push    offset at_mode
                push    ComHandle
                call    WriteFile
                cmp     eax, 0
                jnz     @@write_ok
                push    ComHandle
                call    CloseHandle
                mov     eax, -1
                jmp     @@exit
@@write_ok:
                push    ComHandle
                call    CloseHandle
                mov     eax, 0
@@exit:
                leave
                retn
Switch_mode     endp
Switch_modeLAN     proc near
                push    ebp
                mov     ebp, esp
                invoke lstrcpy,addr bufferx,addr cmdUSBLAN
                invoke lstrcat,addr bufferx,addr arrow
                invoke lstrcat,addr bufferx,addr keyval_buf
				invoke logstat,offset bufferx
				invoke lstrcpy,addr bufferx,StrAddr("\\.\")
				invoke lstrcat,addr bufferx,addr keyval_buf
                push    NULL ;-1
                push    0
                push    OPEN_EXISTING ;1 ; Create new
                push    NULL ;0
                push    0
                push    0C0000000h ; generic RW
                push    offset bufferx ;keyval_buf
                call    CreateFileA
                mov     ComHandle, eax
                cmp     eax,0
                jnz     @@create_ok
                mov     eax, -1
                jmp     @@exit
@@create_ok:
                ;
                ; set COM params
                ;
                invoke GetCommState,ComHandle,addr dcb
                mov dcb.BaudRate,CBR_115200
				mov dcb.ByteSize,8
				mov dcb.Parity,0
				mov dcb.StopBits,0
                invoke SetCommState,ComHandle,addr dcb
                
				invoke lstrcpy,addr bufferx,addr cmdUSBLAN
				invoke lstrcat,addr bufferx,addr crlf
				invoke lstrcat,addr bufferx,addr cmdUSBLAN
				invoke lstrcat,addr bufferx,addr crlf
				;invoke logstat,offset bufferx
                push    0
                push    offset at_readed
                invoke lstrlen,addr bufferx
                push    eax
                push offset bufferx
                push    ComHandle
                call    WriteFile
                cmp     eax, 0
                jnz     @@write_ok
                push    ComHandle
                call    CloseHandle
                mov     eax, -1
                jmp     @@exit
@@write_ok:
                push    ComHandle
                call    CloseHandle
                mov     eax, 0
@@exit:
                leave
                retn
Switch_modeLAN     endp
SwitchFromDataCard proc near 
           push 12h
           push 0
           push 0
           push offset guidMassStorage
           call SetupDiGetClassDevsA
           cmp  eax,-1
           jz @@failed1
           mov  hDeviceInfo, eax
           
           mov  dwMSDevCount,0
           
@@loop1:
           push offset DeviceInterfaceData
           push dwMSDevCount
           push offset guidMassStorage
           push 0
           push hDeviceInfo
           call SetupDiEnumDeviceInterfaces
           inc  dwMSDevCount
           cmp  eax,0
           jz   @@loop_done

           push 0
           push offset DeviceInterfaceDetailDataSize
           push 0
           push 0
           push offset DeviceInterfaceData
           push hDeviceInfo
           call SetupDiGetDeviceInterfaceDetailA

           push DeviceInterfaceDetailDataSize
           push 0
           call GlobalAlloc
           mov  pDeviceInterfaceDetailData, eax
           push esi
           mov  esi, pDeviceInterfaceDetailData
           mov  dword ptr [esi], 5h
           pop esi
           push 0
           push 0
           push DeviceInterfaceDetailDataSize
           push pDeviceInterfaceDetailData
           push offset DeviceInterfaceData
           push hDeviceInfo
           call SetupDiGetDeviceInterfaceDetailA

           mov  eax, pDeviceInterfaceDetailData
           add  eax, 4
           mov  lpMSDevicePath, eax

           push offset lpDevMoto
           push lpMSDevicePath
           call StrStrI
           cmp  eax,0
           jz   @@not_moto

           invoke logstat,StrAddr ("Memcard mode found, swithcing to P2k mode...")

           push 0
           push 20000000h
           push 00000003h
           push 0
           push 00000003h
           push 0C0000000h
           push lpMSDevicePath
           call CreateFileA
           mov  hMSDevice,eax

           push 0
           push offset nBytesReturned
           push 2Ch
           push offset SwitchModePacket
           push 2Ch
           push offset SwitchModePacket
           push 0004D014h
           push hMSDevice
           call DeviceIoControl

           push hMSDevice
           call CloseHandle 


@@not_moto:
           push pDeviceInterfaceDetailData
           call GlobalFree
           jmp  @@loop1           
           
@@loop_done:           
           
@@failed1:           
                   retn
SwitchFromDataCard endp

FindUSBClass    proc near
                push    ebp
                mov     ebp, esp
                pusha
; get classinfoset
                push    12h             ; flags
                push    0               ; parent_hwnd
                push    0               ; enum
                push    offset DevClass ; class GUID
                call    SetupDiGetClassDevsA
                cmp     eax, -1
                jz      @@getclass_fail
                mov     ClassInfoSet, eax

                mov     DevIF_Index, 0
; get DevIF_Data
@@loop:
                push    offset DevIF_Data   ; DevIFData
                push    DevIF_Index         ; dev index
                push    offset DevClass     ; IF class GUID
                push    0                   ; dev info data
                push    ClassInfoSet
                mov     DevIF_Data, 1Ch     ; size
                call    SetupDiEnumDeviceInterfaces
                test    eax, eax
                jz      @@exit ; @@dev_enum_failed ; +
; query size
                push    0                    ; DevInfoData
                push    offset DevIF_ReqSize ; ReqSize
                push    0                    ; DevIFDetailSize
                push    0                    ; DevIFDetail
                push    offset DevIF_Data    ; DevIFData
                push    ClassInfoSet
                call    SetupDiGetDeviceInterfaceDetailA
                test    eax, eax
                jnz     @@dev_info_noerr

                call    GetLastError
                cmp     eax, 7Ah        ; err_insuff_buffer
                jnz     @@exit ; _Destroy_list
; alloc buf
@@dev_info_noerr:
                push    DevIF_ReqSize ; 5Ah?
                push    40h
                call    GlobalAlloc
                mov     esi, eax
                test    esi, esi
                jz      @@exit ; _Destroy_list
; get details
                mov     dword ptr [esi], 5
                push    0               ; DevInfoData
                push    0               ; DevIF_Req_Size
                push    DevIF_ReqSize   ; DevIFDetailSize
                push    esi             ; DevIFDetail - dd size and str - path
                push    offset DevIF_Data ; DevIFData
                push    ClassInfoSet    ; devinfoset
                call    SetupDiGetDeviceInterfaceDetailA
                test    eax, eax
;                jz      @@Dev_GetDetail_failed
                jz      @@fail_gonext

				;DbgDump esi,DevIF_ReqSize
				xor eax,eax
				mov al,[esi+22h]
				mov edi,offset InterfaceIndexStr
				mov [edi+21],al
				.if isIIndexManual==0
					and al,0fh
					mov InterfaceIndex,eax
				.endif
                push    0
                push    0
                push    3
                push    0
                lea     edi, [esi+4]    ; DevIF path
                push    3
                push    0C0000000h
                push    edi
                call    CreateFileA  ;create deviceID handle
                mov     ebx, eax
                cmp     ebx, 0FFFFFFFFh
                jnz @f
                jmp @@fail_gonext
                ;jz      short @@fail_gonext
@@:             mov     _DevIF, ebx

                push    offset str_buf
                push    0102h			; get which info command old=2 Tci 1=MCU+Tci+Accy ** 102h ??

                call    USB_GetIFInfo

				.if isVerboseLog==1
					invoke logstat,offset str_buf	
					invoke logstat,offset InterfaceIndexStr	
				.endif
				;DbgDump offset str_buf,64

                push    offset str_motorola_tci
                push    offset  str_buf
                call    lstrcmpA
                cmp     eax, 0
                jnz     @@not_tci
;                push    edi
;                mov     eax, DevIF_Index
;                mov     [NamesArr_Buf+eax*4], esi
				
                mov     Dev_Name_Ptr, esi
                jmp     @@exit
@@not_tci:
                push    ebx
                call    CloseHandle
                inc     DevIF_Index
                jmp     @@loop

@@fail_gonext:
                push    esi
                call    GlobalFree
                inc     DevIF_Index
                jmp     @@loop

;@@dev_enum_failed:
;                call    GetLastError
;                jmp     @@exit_Destroy_list

;@@Dev_GetDetail_failed:
;                push    esi
;                call    GlobalFree

@@exit:
                push    ClassInfoSet
                call    SetupDiDestroyDeviceInfoList

				mov eax,InterfaceIndex
   	            .if InterfaceIndex==0 && isCDMA05==0
       	        	mov InterfaceIndex,8
           	    .endif
                
@@getclass_fail:
                popa
                leave
                retn
FindUSBClass    endp

File_GetFreeSpace proc near
arg_0           = dword ptr 8

                push    ebp
                mov     ebp, esp

                push    ecx
                push    edx
                push    ebx
                push    esi
                push    edi

;                cmp     TCI_IF, -1
;                jz      @@fail


                mov     byte ptr Cmd_Recv_Buf, 0
                mov     dword ptr Cmd_Send_Buf, 0B000000h ; Cmd
                mov     edi, offset Cmd_Send_Buf
                mov     esi, [ebp+arg_0]
                mov     ecx, 4
                mov     word ptr [edi+ecx], 0600h  ; ARGSIZE
                add     ecx,2

                mov     byte ptr [edi+ecx], 0
                inc     ecx
                mov     al,[esi]
                mov     [edi+ecx],al  ;"/"
                inc     esi
                inc     ecx

                mov     byte ptr [edi+ecx], 0
                inc     ecx
                mov     al,[esi]
                mov     [edi+ecx],al	;0
                inc     esi
                inc     ecx

                mov     byte ptr [edi+ecx], 0
                inc     ecx
                mov     al,[esi]
                mov     [edi+ecx],al    ;"a" or "b"
                inc     esi
                inc     ecx
                
                mov     word ptr [edi+ecx], 0 ;0
                ;add     ecx,2 ; allsize
                

                push    offset Cmd_Recv_Size
                push    offset Cmd_Recv_Buf
                push    ecx
                push    offset Cmd_Send_Buf
                push    004Ah                   ; FSAC
                ;push    TCI_IF
			    ;DbgDump offset Cmd_Send_Buf,64
                call    P2K_SendCommand
                cmp     eax, 0
                jnz     @@fail
                cmp     word ptr Cmd_Recv_Size, 1
                jz      @@fail
                cmp     byte ptr [esi], 6
                jz      @@fail
              
                mov     edx, dword ptr Cmd_Recv_Buf
                xchg    dh, dl
                rol     edx, 10h
                xchg    dh, dl
                mov     eax,edx
                cmp     edx, 0                      ; in edx size of free space
              
                jnz     @@exit

@@fail:
                mov     eax, -1
@@exit:
                pop     edi
                pop     esi
                pop     ebx
                pop     edx
                pop     ecx
                leave
                retn    4
File_GetFreeSpace endp
CheckP2kStatusThread proc hWin:HWND
ThreadinitP2k:     
				invoke DevMonitor_Proc
				.if _DevIF!=0
					mov P2kStatus,1
					invoke logstat,StrAddr ("P2k Tci IF up.")
					invoke GetVolInfo
					; set CB icons
					invoke SendMessage,hLB1,CB_SETITEMDATA,4,P2kIconIndex
					invoke SendMessage,hLB2,CB_SETITEMDATA,4,P2kIconIndex
					invoke EnableWindow,hF6,TRUE
					mov     eax, Dev_Name_Ptr
	                add     eax, 4
	                push    eax
	                push    offset str_devclass_key
	                push    offset str_buf
	                call    wsprintfA
	                add     esp, 0Ch
	                mov     byte ptr [str_buf+56h], '#'
	                mov     byte ptr [str_buf+57h], '#'
	                mov     byte ptr [str_buf+59h], '#'
	
	                push    offset Key_Class_handle  ; handle
	                push    20019h         ; access mask
	                push    0              ; res
	                push    offset str_buf ; subkey
	                push    80000002h      ; key
	                call    RegOpenKeyExA
	
	                push    0 ; async flag
	                push    0; Key_Event
	                push    5 ;notify filter - name+last_set
	                push    1 ; flag subkey notify
	                push    Key_Class_handle
	                call    RegNotifyChangeKeyValue
	
	                push    Key_Class_handle
	                call    RegCloseKey
	;                cmp     Mon_CB, 0
	;                jz      @@skip_cb_off
	;                push    0
	;                call    Mon_CB
	;@@skip_cb_off:
	;                push    Dev_Name_Ptr
	;                call    GlobalFree
	;
	;                mov     DevFound, 0
					mov P2kStatus,0
					mov _DevIF,0
					invoke logstat,StrAddr ("P2k Tci IF down.")
					invoke SetP2kCB1,hWin
					invoke SetP2kCB2,hWin
					invoke EnableWindow,hF6,FALSE
		invoke GetMsgAddr,77
		invoke SetStatusText, 3, 0,eax ; ADDR szType		; set style / text		
		invoke GetMsgAddr,78
		invoke SetStatusText, 1, 0,eax ; ADDR szName		; set style / text		
		invoke GetMsgAddr,79
		invoke SetStatusText, 2, 0,eax ; ADDR szFiles	; set style / text		
		invoke GetMsgAddr,80
		invoke SetStatusText, 0, 0,eax ; ADDR szFree		; set style / text		
				.endif
                push    1388h
                call    Sleep
                jmp     ThreadinitP2k
CheckP2kStatusThread endp
CheckUSBLANStatusThread proc hWin:HWND
ThreadinitU:    
				invoke DevMonitor_ProcLAN
				.if _DevIF!=0
					.if LANStatus==0
						invoke logstat,StrAddr ("USBLAN IF up.")
					.endif	
					mov LANStatus,1
				.endif	
                push    200h ;1388h
                call    Sleep
                jmp     ThreadinitU
CheckUSBLANStatusThread endp
CheckP2k05 proc uses ebx
				mov isP2k05,1
				mov isCDMA05,1
				mov isCDMA,1
				mov stay_quiet,1
				.if ManualP2k05==0
					mov P2k05_Timeout,3e8h
			        push    offset keyval_buf2
	                push    8
	                push    0
	                push    1
	                push    4
	                invoke Cmd_RDELEM
;	                push    offset volname
;	                call    FSAC_GetVolName
	                test    eax, eax
	                jz      @@exit
					mov isP2k05,0
					mov isCDMA05,0
				.endif	
@@exit:			; p2k vs p2k05 decided
		        push    offset keyval_buf2
                push    8
                push    0
                push    1
                push    4
                invoke Cmd_RDELEM
				mov esi,offset keyval_buf2
				mov eax,dword ptr [esi+4]
				.if dword ptr [esi+4]!=0
					mov isCDMA,0
					mov isCDMA05,0
				.endif
				mov P2k05_Timeout,1388h
				mov stay_quiet,0
				ret
CheckP2k05 endp
P2K_AT proc
	        mov     packet_size,9
    	    push    offset packet_size
        	push    offset SwitchToAT_Buff
        	call    USB_WriteData
			ret
P2K_AT endp

ezxname 	proc
				push 0ffffffffh ;AttribHW
				push offset ezxBT ;NameHW
				call FSAC_open
				push 0
				push 0
				call FSAC_seek
				MOV P2kFilesize,500
				invoke GlobalAlloc,GMEM_FIXED or GMEM_ZEROINIT,P2kFilesize
				mov	hMemFile,eax
				push P2kFilesize
				push hMemFile
				invoke FSAC_read
				invoke FSAC_close
				; search
				invoke BinSearch,0,hMemFile,500,StrAddr("defaultLocalDevName"),19
				.if eax!=-1
 					mov esi,hMemFile
 					add esi,eax
 					add esi,22
 					push esi
 					; search end (0ah)
 					.while byte ptr [esi]!=0ah
 						inc esi
 					.endw
 					mov byte ptr [esi],0
 					pop esi
					invoke lstrcpy,addr EzxModel,esi
				.endif	
				invoke GlobalFree,hMemFile
				ret
ezxname endp