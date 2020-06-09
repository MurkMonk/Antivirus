#pragma once
#include <iostream>
#include<windows.h>

/*	ОБЪЯВЛЕНИЕ КЛАССА ОПИСЫВАЮЩЕГО ОБЪЕКТЫ СКАНИРОВАНИЯ
*Осуществляет поиск в файлах атрибутов принадлежности к PE-файлам
*Podolski
*/

class ScanObject
{
public:
	virtual unsigned char* GetbaseAddress() = 0;
	virtual	unsigned __int64 Getlength() = 0;
	virtual ~ScanObject() {}
};

class ConcreteScanObject : public ScanObject
{
	std::string name;
	LPBYTE fileMapping;
	unsigned char* baseAddress;
	unsigned __int64 codeSegOffset;
	unsigned __int64 length;
public:
	ConcreteScanObject() { fileMapping = NULL; }
	ConcreteScanObject(std::string name, LPBYTE fileMapping, unsigned char* baseAdress, unsigned __int64 codeSegOffset, unsigned __int64 length)
	{
		this->name = name;
		this->fileMapping = fileMapping;
		this->baseAddress = baseAdress;
		this->codeSegOffset = codeSegOffset;
		this->length = length;
	}

	unsigned char* GetbaseAddress()
	{
		return this->baseAddress;
	}

	void setBaseAddress(unsigned char*value)
	{
		this->baseAddress = value;
	}

	unsigned __int64 Getlength()
	{
		return this->length;
	}

	void setLength(const unsigned __int64 &value)
	{
		this->length = value;
	}

	std::string GetObjectName() const
	{
		return this->name;
	}

	void setName(const std::string &value)
	{
		this->name = value;
	}

	unsigned __int64 getCodeSegOffset() const
	{
		return this->codeSegOffset;
	}
	void setCodeSegOffset(const unsigned __int64 &value)
	{
		this->codeSegOffset = value;
	}
	LPBYTE getHFile() const
	{
		return this->fileMapping;
	}
	void setHFile(LPBYTE value)
	{
		this->fileMapping = value;
	}
};
