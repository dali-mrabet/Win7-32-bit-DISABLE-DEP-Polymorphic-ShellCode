*******************************************************
* written by : Mohamed ali Mrabet                     *
* facebook :   https://www.facebook.com/dali.mrabet.3 *
* Blog :       http://dali-mrabet1.rhcloud.com/        *
*                                                     *
*******************************************************


//Using any part of this code for malicious purposes is expressly forbidden.


#include "stdafx.h"
#include <windows.h>

//don't optimize my code , leave the opcodes unaltered !!
#pragma optimize("",off)


typedef struct
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;

}  UNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };

    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY;



int _tmain(int argc, _TCHAR* argv[])
{

typedef long long int (  WINAPI * ProcAddress)( IN HMODULE  , IN LPCSTR ) ;
typedef HMODULE ( WINAPI * LoadLibrar)(IN LPCTSTR lpFileName) ;
typedef int (WINAPI * SetProcessDEPPolicyy)( IN int flag) ;

UNICODE_STRING  sh ;
    WCHAR kernel_32dll[13] ;
    kernel_32dll[0] ='k' ;
    kernel_32dll[1] ='e' ;
    kernel_32dll[2] ='r' ;
    kernel_32dll[3] ='n';
    kernel_32dll[4] ='e';
    kernel_32dll[5] ='l';
    kernel_32dll[6] ='3';
    kernel_32dll[7] ='2';
    kernel_32dll[8] ='.';
    kernel_32dll[9] ='d';
    kernel_32dll[10]='l';
    kernel_32dll[11]='l';
    kernel_32dll[12]= 0x0;

    /*well , this is the weirdest thing I have ever seen in programming .
      Using Gcc Compiler , It does work if and only if the function pointer(myGetProcAdd) is declared as static variable,
      whereas the  myloadLibrary function pointer works with no issues (without 'static' prefix),
      during the run-time , it generates the NTSTATUS "PRIVILGED_INSTRUCTION_ERROR".
      This crap took me nearly the whole day to work it out , and still have no idea from where the error stems !!
      !! such a HEADACHE!!
     */
/*static*/ ProcAddress myGetProcAdd ;
LoadLibrar  myLoadLibrary ;
SetProcessDEPPolicyy mySetProcessDEPPolicy ;
sh.Buffer = kernel_32dll;
sh.Length = 0x0 ;
sh.MaximumLength = 13 ;
int i = 0 ;
PVOID Kernel32_DllBase = 0 ;
IMAGE_DOS_HEADER * idh = 0 ;
IMAGE_NT_HEADERS * inh = 0 ;
DWORD  export_va = 0 ;
LDR_DATA_TABLE_ENTRY * ldte = 0x0 ;

__asm
{
    mov eax,dword ptr fs:[0x30]
    mov eax,dword ptr [eax+0xC]
    mov ebx,dword ptr [eax+0xC] //ldr_data_table_entry
    mov ss:[ldte] , ebx
} ;


while(1)
{
    for(i = 0 ; i < 12 ; i++)
    {
        if(sh.Buffer[i] != ldte->BaseDllName.Buffer[i])
        {
            break ;
        }
    }
    if (i == 12 )
    {
        Kernel32_DllBase = ldte->DllBase ;
        break ;
    }
    ldte = (LDR_DATA_TABLE_ENTRY * )ldte->InLoadOrderLinks.Flink ;
}

idh = (IMAGE_DOS_HEADER * )Kernel32_DllBase ;
inh = (IMAGE_NT_HEADERS * )((DWORD)Kernel32_DllBase + idh->e_lfanew );
export_va =  inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress ;

IMAGE_EXPORT_DIRECTORY * iid = (IMAGE_EXPORT_DIRECTORY * )((DWORD) Kernel32_DllBase + export_va );

int *  AddressOfNames =(int * ) ((DWORD)Kernel32_DllBase + iid->AddressOfNames) ;
int  * AddresseOffuncs =(int * ) ((DWORD)Kernel32_DllBase + iid->AddressOfFunctions );

char getprocaddress[15] ;
getprocaddress[0] = 'G';
getprocaddress[1] = 'e';
getprocaddress[2] = 't';
getprocaddress[3] = 'P';
getprocaddress[4] = 'r';
getprocaddress[5] = 'o';
getprocaddress[6] = 'c';
getprocaddress[7] = 'A';
getprocaddress[8] = 'd';
getprocaddress[9] = 'd';
getprocaddress[10] = 'r';
getprocaddress[11] = 'e';
getprocaddress[12] = 's';
getprocaddress[13] = 's';
getprocaddress[14] = 0x0;

char loadlibrarya[13] ;
loadlibrarya[0] = 'L';
loadlibrarya[1] = 'o';
loadlibrarya[2] = 'a';
loadlibrarya[3] = 'd';
loadlibrarya[4] = 'L';
loadlibrarya[5] = 'i';
loadlibrarya[6] = 'b';
loadlibrarya[7] = 'r';
loadlibrarya[8] = 'a';
loadlibrarya[9] = 'r';
loadlibrarya[10] = 'y';
loadlibrarya[11] = 'A';
loadlibrarya[12] = 0x0 ;

int   loadisfound = 0 ,getprocisfound = 0, len = 15, j = 0 ;
char * kernel32_temp = 0x0 ;
char * temp = getprocaddress;

//Can Ya Dig It :P !!
while(i < iid->NumberOfNames )
{

    if(getprocisfound == 1)
    {
        len  = 13 ;
        temp = loadlibrarya ;
    }
    kernel32_temp = (char * )( (DWORD)Kernel32_DllBase + AddressOfNames[i] );
    for (j = 0; j < len ; j++ )
    {
        if(temp[j] != *(kernel32_temp+j))
            break ;
    }
    if(j == len )
    {
        if(getprocisfound == 1 )
        {
            myLoadLibrary = (LoadLibrar)((DWORD)Kernel32_DllBase + AddresseOffuncs[i]);
            loadisfound = 1 ;
            break ;
        }
        else
        {
            getprocisfound = 1 ;
            myGetProcAdd =(ProcAddress)((DWORD)Kernel32_DllBase + (DWORD)AddresseOffuncs[i+1]) ;
        }
    }
    i++ ;
}

char DEP[20] ;
DEP[0] = 'S' ;
DEP[1] = 'e' ;
DEP[2] = 't' ;
DEP[3] = 'P' ;
DEP[4] = 'r' ;
DEP[5] = 'o' ;
DEP[6] = 'c' ;
DEP[7] = 'e' ;
DEP[8] = 's' ;
DEP[9] = 's' ;
DEP[10] = 'D' ;
DEP[11] = 'E' ;
DEP[12] = 'P' ;
DEP[13] = 'P' ;
DEP[14] = 'o' ;
DEP[15] = 'l' ;
DEP[16] = 'i' ;
DEP[17] = 'c' ;
DEP[18] = 'y' ;
DEP[19] = 0x0 ;

//manual import of SetProcessDEP API !!
mySetProcessDEPPolicy = (SetProcessDEPPolicyy)myGetProcAdd((HMODULE)Kernel32_DllBase,DEP);

// mySetProcessDEPPolicy(0);
mySetProcessDEPPolicy(0) ;
//disable DEP for the cuurent Process !!

return 0;
}
