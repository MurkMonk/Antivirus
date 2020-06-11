#include "pch.h"
#include "ScanEngine.h"

//Zarija
void ScanEngine::update(ConcreteScanObject* obj)
{
	Scan(obj);
}

void ScanEngine::Scan(ConcreteScanObject* obj)
{
	if (obj->getHFile() == NULL) return;
	LPBYTE startPoint = (obj->getHFile() + obj->getCodeSegOffset());
	char firstBytes[9];
	for (int offset = 0; offset < (obj->Getlength() - 8); offset++)	
	{
		strncpy(firstBytes, (char*)&startPoint[offset], 8);
		firstBytes[8] = '\0';
		
		for (std::map<std::string,AVRecord> base : bases)
		{
			std::string tmp(firstBytes);
			if (base.find(tmp) == base.end()) continue;
			AVRecord record = base.at(firstBytes);
			if (record.Signature->getRAW()[0] <= offset && record.Signature->getRAW()[1] > offset)
			{
				int signLen = record.Signature->getLenght();
				char* signature = new char[signLen];
				strncpy(signature, reinterpret_cast<char*>(&startPoint[offset]), signLen);
				if (getStringHash(std::string(signature)) == record.Signature->getHash())
				{
					std::cout <<"Virus Detected!\nVirus Name:"<< record.getName() << " in " << obj->GetObjectName() << std::endl;
				}
			}

		}
	}
}
