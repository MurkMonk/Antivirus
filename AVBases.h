#pragma once
#include "avrecord.h"
#include <map>

/*КЛАСС ДЛЯ РАБОТЫ С ФАЙЛОМ БД
 Podolski
*
Формат файла антивирусной базы:

	*	Последовательность бит для идентификации{сигнатура, подтверждающая что данный файл АНТИВИРУСНАЯ БАЗА};
	*	Число записей в базе;
	*	[Последовательность записей ... ];

*/


//! Класс описания содержимого файла антивирусной базы
class AVDataBaseFile{
public:	std::fstream OpeningFile; // - Объект потока открываемого файла
protected:
	const char *ADBsignature="KaSpErSki_BVT1702";// - идентификационная сигнатура файла НАШЕЙ БД.
	int RecordCount; // - Число записей
		
	//конструктор по-умолчанию
public:
	AVDataBaseFile(){
		this->RecordCount = 0;
	}
	//проверка на существование указанного файла
	inline bool is_file_exist(const char *fileName)
	{
		std::ifstream fileExist(fileName);
		return fileExist.good();
	}

	//! Закрытие файла
	 void close();
	//! Получение числа записей
	 int getRecordCount();
	 void setRecordcount(int count) { this->RecordCount = count; }
};


//! Класс для записи файла
class AVDataBaseFileWriter : public AVDataBaseFile{
public:
	AVDataBaseFileWriter() : AVDataBaseFile()// -конструктор класса AVDataBaseFileWriter вызывает конструктор класса AVDataBaseFile
	{
	}
	//! Открытие файла
	bool open(char* FileName);
	//! Добавление записи в файл 
	bool addRecordIntoFile(AVRecord *Record);

};

//! Класс для чтения файла
class AVDataBaseFileReader : public AVDataBaseFile{
public:
	AVDataBaseFileReader() : AVDataBaseFile(){}// -конструктор класса AVDataBaseFileReader вызывает конструктор класса AVDataBaseFile
	//! Открытие файла
	int open(char* FileName);
	//! Чтение записи
	bool readNextRecord(AVRecord *Record);
	
	
	void readFromDataBase(std::map<std::string, AVRecord>* signatureTree);

};
