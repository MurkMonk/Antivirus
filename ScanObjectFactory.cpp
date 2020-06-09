#pragma once
#include "pch.h"
#include<windows.h>
#include <fstream>
#include"PE_parser.h"
#include"ScanObject.h"
#include"ScanObjectFactory.h"
//Podolski
//создаем файловое отображение
LPBYTE PEObjectFactory::OpenFile(std::string path) {
	HANDLE hFile = CreateFileA((path.c_str()), GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		std::cout <<GetLastError() <<std::endl;
		//throw std::exception("File open error!");
		return NULL;
	}
	HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	CloseHandle(hFile);
	LPBYTE pBase = NULL;
	if (hMapping != NULL) {
		pBase = (LPBYTE)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
		CloseHandle(hMapping);
	}

	return pBase;
}
//закрываем файловое отображение
void PEObjectFactory::CloseFile(LPBYTE pBase) {
	if (pBase != NULL)
		UnmapViewOfFile(pBase);
}
//функция создания объектов сканирования
ConcreteScanObject* PEObjectFactory::createObject()
{
	return new ConcreteScanObject();
}
ConcreteScanObject* PEObjectFactory::createObject(std::string name, LPBYTE fileMapping, unsigned char* baseAdress, unsigned __int64 codeSegOffset, unsigned __int64 length) 
{
	return new ConcreteScanObject(name, fileMapping, baseAdress, codeSegOffset, length);
}

//Сообщаем наблюдателю о том, что обЪект сканирования произведен фабрикой
void PEObjectFactory::update(std::string path_to_PE)
{
	LPBYTE res = OpenFile(path_to_PE); //пытаемся открыть файловое отображение
	if (res == NULL) return;					//если не открылось

	PEParser* myParser = new PEParser(res);
	if (myParser->Its_PE() == 0)				//если файл, отображенный на память не является РЕ
	{
		setState(createObject());
		
	}
	else
	{
		//получаем EXE-секцию
		IMAGE_SECTION_HEADER*ExeSecHeader = myParser->GetEXESection();
		//получаем смещение до секции
		DWORD PointerToRawData = ExeSecHeader->PointerToRawData;
		//получаем размер секции
		DWORD SizeOfRawData = ExeSecHeader->SizeOfRawData;
		//получаем виртуальный адрес секции
		DWORD VirtualAddress = ExeSecHeader->VirtualAddress;
		LPBYTE baseAddr = myParser->GetSectPointer(res, VirtualAddress);
		//сообщаем наблюдателю, что фабрика создала объект для сканирования
		setState(createObject(path_to_PE, res, baseAddr, PointerToRawData, SizeOfRawData));
	}
}
