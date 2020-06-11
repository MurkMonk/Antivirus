#pragma once
#include "avrecord.h"
#include "AVBases.h"
#include "ScanDir.h"
#include "ScanObject.h"

/*	ОБЪЯВЛЕНИЕ КЛАССА СКАНЕРА ВИРУСОВ
*	Nizhnic
*/
class ScanEngine :public Observer<ConcreteScanObject*>
{
	std::vector <std::map<std::string,AVRecord>> bases;
	std::vector <std::string> virus_info;
	void update(ConcreteScanObject* obj) override;
	
	void Scan(ConcreteScanObject* obj);
public:
	ScanEngine()	{}
	void addBase(std::map<std::string, AVRecord> base) {
		bases.push_back(base);
	}
};
