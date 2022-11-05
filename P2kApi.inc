.data

str_motorola_tci db 'Motorola Test Command',0
;str_motorola_tci db 'MCU Logging+test cmd+accy',0
str_seem_fn     db 'xxxx_yyyy.seem', 0
str_serialcom_key db 'HARDWARE\DEVICEMAP\SERIALCOMM',0
str_serialcom_key2 db 'HARDWARE\DEVICEMAP\SERIALCOMM',0
str_devclass_key  db 'SYSTEM\CurrentControlSet\Control\DeviceClasses\{4e1e1e15-52d7-11d4-852d-00105aa6f80b}\%s\#\Control',0
str_usbser        db '\Device\USBSER000', 0
str_usbser2        db 'USBPDO-',0 ;3', 0
str_usbser3        db '0000',0 ;3', 0
at_mode           db 'at+mode=8', 0Dh, 0Ah, 0
at_modeLAN        db 'at+mode=13', 0Dh, 0Ah, 0dh,0ah,0

Dev_Name_Ptr    dd 0

ClassInfoSet    dd 0
DevIF_Index     dd 0

DevIF_Data      dd 0 ; size
DevIF_GUID      dd 0
DevIF_Flags     dd 0
DevIF_res       dd 0
                dd 0
                dd 0
                dd 0


DevIF_ReqSize   dd 0

DevClass        dd 4E1E1E15h, 11D452D7h, 10002D85h, 0BF8A65Ah

DevIO_Overlapped  dd 0
                  dd 0
                  dd 0
                  dd 0
DevIO_Event       dd 0
DevIO_Result      db 1010h dup (?) ; 1008h
;-----------------------------
CommTimeouts       dd ?
CommTimeouts_Multi dd ?
CommTimeouts_Const dd ?
CommTimeouts_W_Multi dd ?
CommTimeouts_W_Const dd ?

ComHandle       dd ?
at_readed       dd ?
Key_handle      dd ?
Key_Class_handle dd ?
keyval_type     dd ?
keyval_size     dd ?
keyval_size2     dd ?
keyval_buf      db 100h dup (?)
keyval_buf2     db 100h dup (?)

; FSAC_Read data
FSAC_Read_Bufs_Copyed dd ?
FSAC_Read_BufPos      dd ?

Download_BufPtr dd ?
Download_FSize  dd ?

stelem_result   dd ?
seem_read_bytes dd ?

seem_num        dw ?
seem_rec        dw ?
seem_ofs        dw ?
seem_bytes      dw ?
seem_data       db 2710h dup (?)
seem_data2       db 2710h dup (?)

rec_no          dd ?
seem_no         dd ?
seem_to         dd ?


Cmd_Send_Size    dd ?
Cmd_Recv_Size    dd ?
Cmd_Send_Buf     db 1000h dup (?)
Cmd_Recv_Buf     db 1000h dup (?)

Packet_ID        dw ?
                 dw ?
packet_size      dd ?
packet_buf       db 1000h dup (?)
status_read_size dd ?
status_read_buf  db 0Ch dup (?) ; 0Ch bytes
data_read_size   dd ?
data_read_buf    dd 1000h dup (?)
ReadStatus_Ticks dd ?

IF_Info_cmd      dd ?
IF_Info_recvd    dd ?

str_buf         db 1000h dup (?)
volname         db 100h dup (?)
lv_get_text     db 200h dup (?)
fname_buf       db 200h dup (?) ; buffer for open/save full filename
fname_t_buf     db 200h dup (?) ; buffer for open/save short filename (w/o path)
seem_buf        db 1000h dup (?)

ini_file        db 100h dup (?)

;msg_inv_data_len db "INVALID DATA LENGTH FOR COMMAND.",0 ; 0
;msg_inv_seq      db "INADEQUATE SEQURITY LEVEL FOR COMMAND/PARAMETER.",0 ; 1
;msg_cmd_par_inv  db "COMMAND/PARAMETER NOT SUPPORTED FOR CURRENT PROTOCOL.",0 ; 2
;msg_cmd_not_supp db "COMMAND NOT SUPPORTED FOR CURRENT MODE.",0 ; 3
;msg_inv_opcode   db "UNSUPPORTED/INVALID OPCODE.",0 ; 4
;msg_inv_param    db "UNSUPPORTED/INVALID PARAMETER FOR OPCODE.",0 ; 5
;msg_err_code_unk_6 db "CRITICAL ERROR - ERROR CODE NOT FOUND (6).",0 ; 6
;msg_generic_fail db "GENERIC FAILURE.",0 ;7
;msg_err_code_unk_8 db "CRITICAL ERROR - ERROR CODE NOT FOUND (8).",0 ; 8
;msg_err_code_unk_9 db "CRITICAL ERROR - ERROR CODE NOT FOUND (9).",0 ; 9
;msg_mem_fail     db "COULDN""T ALLOCATE MEMORY.",0  ; 10
;msg_task_error   db "INTERNAL TASK ERROR.",0 ; 11
;msg_task_timeout db "TEST COMMAND TASK TIMED OUT WAITING FOR RESPONSE.",0 ; 11
;msg_cdma_err     db "CDMA PARSE ERROR.",0 ; 13
;msg_len_error    db "LENGTH SPECIFIED IN COMMAND HEADER GREATER THAN RECEIVED BY TRANSPORT.",0 ; 14
;msg_crit_error   db "IRRECOVERABLE ERROR; PHONE STATE HAS BEEN LOST. PHONE BEING POWERED DOWN.",0 ; 15

; log strings

;str_FSAC_Info    db "Volume information -->",0  ; 16
;str_volname_fail db "Volume name fail!",0 ; 17
;str_volsize_fail db "Volume size fail!",0 ; 18
;msg_volsize_zero db "Zero free space recv'd!",0 ; 19
;str_volname      db "  Name: ",0  ; 20
;str_volsize      db "Free space: ",0  ; 21
;str_kb           db " KBytes",0 ; 22
;str_Files_Added  db " files found.",0 ; 23


;msg_cmd_write_fail  db "CMD: Data write fail!",0 ; 24
;msg_cmd_timeout     db "CMD: Answer wait timeout!",0 ; 25
;msg_cmd_answer_fail db "CMD: Answer packet invalid!",0  ; 26

;msg_usb_write_ok    db "USB: Write data ok.",0 ; 27
;msg_usb_event_fail  db "USB: Event create failed!",0 ; 28
;msg_usb_reset_fail  db "USB: Event reset failed!",0 ; 29
;msg_usb_wait_fail   db "USB: IO Time-out!",0 ; 30
;msg_usb_result_fail db "USB: IO Failed!"  ; 31
;msg_usb_size_fail   db "USB: Answer size invlid!" ; 32


;str_deleting    db "Deleting file ",0 ;33
;str_filesnum    db "Invalid files count!",0 ; 34
;str_malloc_fail db " Memory allocation fail",0 ; 35
;msg_fl_rec_size_fail db "FileList entry size invalid!",0 ; 36

stay_quiet      dd 0

; PSTGetDeviceInterface data
_DevIF          dd 0

Our_Handle      dd 0

crlf            db 0Dh,0Ah,0
fn_mytonedb     db 'MyToneDB.db', 0
str_ctl         db '%.4x_%.4x.seem', 0
str_hex         db '%x', 0
str_hexdw       db '%.4x', 0
str_dec         db '%d', 0

FHandle         dd 0
filesize_ex     dd 0  ; GetFileSize hi dword
FileSize        dd 0
file_readed     dd 0
FileBuf_Ptr     dd 0  ; upload buffer
files_dl_first  dd 0

; Filelist data
Files_found      dd ?
FileList_RecSize dd ?
SearchBuf_Ptr    dd 0
SearchBuf_Pos    dd ?
SearchBuf_Pos2   dd ?
SearchBuf_Size	 dd ?
VolSpace         dd ?

;IO_Err          dd offset msg_inv_data_len
;                dd offset msg_inv_seq
;                dd offset msg_cmd_par_inv
;                dd offset msg_cmd_not_supp
;                dd offset msg_inv_opcode
;                dd offset msg_inv_param
;                dd offset msg_err_code_unk_6 ; resp_ack
;                dd offset msg_generic_fail
;                dd offset msg_err_code_unk_8
;                dd offset msg_err_code_unk_9
;                dd offset msg_mem_fail
;                dd offset msg_task_error
;                dd offset msg_task_timeout
;                dd offset msg_cdma_err
;                dd offset msg_len_error
;                dd offset msg_crit_error
                
;txt_usbport		db "Usb p2k device found, phone connected !",0 ;37
;txt_noport		db "No p2k device found, NOT connected !",0 ;38

DevFound         dd 0
hWinV			 dd 0
isRefresh		 dd 5

InterfaceIndexStr	 db "InterfaceNumber is: 00 ",0
Comindex		dd 0
arrow 			db " --> ",0

P2kStatus		dd 0

guidMassStorage                 db 07h, 63h, 0f5h, 53h, 0bfh, 0b6h, 0d0h, 11h, 94h, 0f2h, 00h, 0a0h, 0c9h, 1eh, 0fbh, 8bh
SwitchModePacket                db 2ch, 00, 00, 00, 00, 00, 0ch, 00, 01, 00, 00, 00, 00, 00, 00, 00, 19h, 00, 00, 00, 00, 00, 00, 00
                                db 00, 00, 00, 00, 0d6h, 00, 00, 00, 00, 00, 00, 00, 00, 00, 08, 00, 00, 00, 00, 00
dwMSDevCount                    dd 00
DeviceInterfaceData             dd 28
                                dd 0h,0h,0h,0h
                                dd 00h
                                dd 00h
pDeviceInterfaceDetailData      dd 00h
DeviceInterfaceDetailDataSize   dd 00h
lpDevMoto                       db 'motorola', 00h
lpMSDevicePath                  dd 00h 
hMSDevice                       dd 00h
nBytesReturned                  dd 00h 
hDeviceInfo                     dd 00h

P2k05_Bulk_Mode					dd 2
P2k05_Bulk_Timeout				dd 1000h
P2k05_Bulk_Inbufsize			dd 0 
P2k_Timeout						dd 1388h
P2k05_Timeout					dd 1388h
isP2k05							dd 0
isCDMA							dd 0
isCDMA05						dd 0

SwitchToAT_Buff  db  40h, 01h, 00h, 00h, 01h, 00h, 00h, 00h, 00h
dcb                     DCB     	 <?>
