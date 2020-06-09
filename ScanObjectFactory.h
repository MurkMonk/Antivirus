#pragma once
#include"ScanObject.h"
#include "Observer.h"
#include "Subject.h"

/*	ОБЪЯВЛЕНИЕ КЛАССА ОПИСЫВАЮЩЕГО ФАБРИКУ
*	Zarija
*/

// Абстрактная фабрика
class ObjectFactory 
{
public:
	virtual ScanObject* createObject() = 0;
	virtual ~ObjectFactory() {}
};


// Фабрика для создания объектов для сканирования 
class PEObjectFactory :  public Observer<std::string>,public Subject<ConcreteScanObject*>
{
public:
	LPBYTE OpenFile(std::string path_to_PE);
	void CloseFile(LPBYTE pBase);
	ConcreteScanObject* createObject();
	ConcreteScanObject* createObject(std::string name, LPBYTE fileMapping, unsigned char* baseAdress, unsigned __int64 codeSegOffset, unsigned __int64 length);
	void update(std::string path_to_PE) override;
	//открываю файл .создаю объект сканирования, setState на scanObject
};
