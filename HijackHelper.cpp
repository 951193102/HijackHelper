#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[])
{
	if (argc < 2) return 0;
	HANDLE hFile = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		HANDLE hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
		CloseHandle(hFile);
		BYTE* pImageBase = (BYTE*)MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
		CloseHandle(hFileMap);
		PIMAGE_DOS_HEADER pimDH = (PIMAGE_DOS_HEADER)pImageBase;
		PIMAGE_NT_HEADERS pimNH = (PIMAGE_NT_HEADERS)(pImageBase + pimDH->e_lfanew);
		PIMAGE_EXPORT_DIRECTORY pimExD = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pImageBase + pimNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		DWORD*  pName        = (DWORD*)((DWORD)pImageBase + (DWORD)(pimExD->AddressOfNames));
		int  NumberOfFunction = pimExD->NumberOfFunctions;
		puts("#pragma once");
		puts("");
		puts("#define  _CRT_SECURE_NO_WARNINGS");
		puts("");
		puts("// 声明导出函数");
		for (int i = 0; i < NumberOfFunction; i++)
		{
			if (LOWORD(pName[i] + (DWORD)pImageBase) == 1)
			{
				//printf("#pragma comment(linker, \"/EXPORT:FN%d=_My_Fun%d,@%d\")\n",i+1,i+1,i+1);
			}
			else printf("#pragma comment(linker, \"/EXPORT:%s=_My_Fun%d,@%d\")\n", pName[i] + (DWORD)pImageBase, i + 1, i + 1);
		}
		puts("");
		puts("// 函数实现,写成宏,简化代码量");
		puts("#define IMPL_STUB_FUNC(n) \\");
		puts("	DWORD g_dwFunPtr##n=0; \\");
		puts("	extern \"C\" void _declspec(naked) My_Fun##n() \\");
		puts("{ \\");
		puts("	__asm jmp DWORD PTR[g_dwFunPtr##n] \\");
		puts("}");
		puts("");
		puts("// 实现跳板函数");
		for (int i = 0; i < NumberOfFunction; i++)
		{
			if (LOWORD(pName[i] + (DWORD)pImageBase) != 1) printf("IMPL_STUB_FUNC(%d);\n", i + 1);
		}
		puts("");
		puts("#define INIT_STUB_FUNC(n,name) \\");
		puts("	g_dwFunPtr##n = (DWORD)GetProcAddress(hDll,name);");
		puts("");
		puts("// 加载系统dll,初始化函数指针");
		puts("void LoadSysDll()");
		puts("{");
		puts("	TCHAR szDLL[MAX_PATH+1];");
		puts("	GetSystemDirectory(szDLL,MAX_PATH);");
		printf("	lstrcat(szDLL,TEXT(\"\\\\");
		printf("%s", argv[1]);
		puts("\"));");
		puts("");
		puts("	HINSTANCE hDll=LoadLibrary(szDLL);");
		puts("	if (hDll!=NULL)");
		puts("	{");
		for (int i = 0; i < NumberOfFunction; i++)
		{
			//if(LOWORD(pName[i]+(DWORD)pImageBase)==1)
			//{
			//	printf("		INIT_STUB_FUNC(%d,(const char*)%d);\n",i+1,i+1);
			//}
			//else
			if (LOWORD(pName[i] + (DWORD)pImageBase) != 1) printf("		INIT_STUB_FUNC(%d,\"%s\");\n", i + 1, pName[i] + (DWORD)pImageBase);
		}
		puts("	}");
		puts("}");
		puts("");
		UnmapViewOfFile(pImageBase);
	}
}
