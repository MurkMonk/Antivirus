// Obs.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//
#pragma once
//Podolski
#include <windows.h>
#include "pch.h"
#include <iostream>
#include <filesystem>
#include "FileWatcher.h"
#include"PE_parser.h"
#include "avrecord.h"
#include"AVBases.h"
#include "ScanEngine.h"
#include "ScanObjectFactory.h"
#include "ScanDir.h"
#include <map>

#pragma region Вспомогательные функции

//преобразование string to wstring
std::wstring s2ws(const std::string& str)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.from_bytes(str);
}
//Преобразование wstring to string
std::string ws2s(const std::wstring& wstr)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.to_bytes(wstr);
}

//проверка расширения БД
size_t find_ext_idx(const char* fileName)
{
	size_t len = strlen(fileName);
	size_t idx = len - 1;
	for (size_t i = 0; *(fileName + i); i++) {
		if (*(fileName + i) == '.') {
			idx = i;
		}
		else if (*(fileName + i) == '/' || *(fileName + i) == '\\') {
			idx = len - 1;
		}
	}
	return idx + 1;
}

bool Check_file_ext(const char* fileName)
{
	std::string extens;

	extens = std::string(fileName).substr(find_ext_idx(fileName));
	if ((extens.compare("MyViRdBase") == 0)) { return 1; }
	return 0;
}
//Nizhnic
#pragma endregion
#pragma region lab5
extern "C" __declspec(dllexport) void __stdcall MyDirWatcher(Subject<std::string> &subj, std::string path) {
	//создаем экземпляр FileWatcher который проверяет изменения в папке(path) каждые 3 секунды
	FileWatcher fw{ path, std::chrono::milliseconds(3000) };

	// запускаем мониторинг изменений
	fw.start(subj, [](std::string path_to_watch, FileStatus status, Subject<std::string> &subj) -> void {
		std::string resStr;
		// выбираем только регулярные файлы
		if (!std::filesystem::is_regular_file(std::filesystem::path(path_to_watch))) {
			return;
		}
		//проверяем переданный статус файла
		switch (status) {
		case FileStatus::created:
			resStr = "File created:"+path_to_watch+"\n";
			std::cout << "\n---------FILE_WATCHER INFO-----------\n\n";
			std::cout << resStr;
			std::cout << "\n-------------------------------------\n\n";
			subj.setState(path_to_watch);
			break;
		case FileStatus::modified:
			resStr = "File modified:" + path_to_watch + "\n";
			std::cout << "\n---------FILE_WATCHER INFO-----------\n\n";
			std::cout << resStr;
			std::cout << "\n-------------------------------------\n\n";
			subj.setState(path_to_watch);
			break;
		default:
			resStr = "Error! Unknown file status.\n";
			std::cout << "\n---------FILE_WATCHER INFO-----------\n\n";
			std::cout << resStr;
			std::cout << "\n-------------------------------------\n\n";
			break;
		}
		
	});
}


#pragma endregion

int main(int argc, const char * argv[]) {

	std::map<std::string,AVRecord>signatureTree; //создаем дерево сигнатур
	AVDataBaseFileReader MyReader;
	AVDataBaseFileWriter MyWriter;//создаем объект класса-писателя для записи в БД бд
	char* filename = new char[12];
	strcpy(filename, "base1");
	MyReader.open(filename);
	MyReader.readFromDataBase(&signatureTree);
	int point = 0;
	std::string watchPath;
	std::wstring scanPath;
	DirScanner* Dirsc;
	Subject<std::string> DirStateWatcher;
	PEObjectFactory factory;
	ScanEngine scanner;
	std::thread* bg = nullptr;
	AVRecord record = AVRecord();
	std::string signature;
	size_t hash = 0;
	std::string name;
	std::string start;
	int16_t lRAW, rRAW, length;
	std::cout << "******** Console Signature Scanner********" << std::endl<<std::endl;
	
	do {
		std::cout << "\nPlease select a function from the list:" << std::endl;
		std::cout << "Input 1 to scan directory\n";
		std::cout << "Input 2 to watch for directory\n";
		std::cout << "Input 3 to add entry\n";
		std::cout << "Input 0 to exit\n";
		std::cin >> point;
		
		switch(point)
		{
		case 1: 
			std::cout << "Input path to directory: ";
			std::wcin >> scanPath;
			std::cout<<"\nScanning...."<<std::endl;
			Dirsc = new DirScanner(scanPath.c_str());
			factory = PEObjectFactory();
			scanner = ScanEngine();
			scanner.addBase(signatureTree);
			Dirsc->attachObserver(&factory);
			factory.attachObserver(&scanner);
			bg = new std::thread(&DirScanner::GetPE_from_Dir, Dirsc);
			bg->join();
			break;
		case 2:
			std::cout << "Input path to directory: ";
			std::cin >> watchPath;
			factory = PEObjectFactory();
			scanner = ScanEngine();
			scanner.addBase(signatureTree);
			DirStateWatcher.attachObserver(&factory);
			factory.attachObserver(&scanner);
			bg = new std::thread(MyDirWatcher, std::ref(DirStateWatcher), watchPath.c_str());
			//bg->join();
			std::cout << "\nThe observer for the directory installed!" << std::endl<<std::endl;
			break;
		case 3:
			std::cout << "Input name: "; std::cin >> name;
			std::cout << "Input offset: "; std::cin >> lRAW >> rRAW;
			std::cout << "Input signature length: "; std::cin >> length;
			std::cout << "Input signature: "; std::cin >> signature;

			hash = getStringHash(std::string(signature));	//получаем хэш
			start = signature.substr(0, 8);					//выделяем первые байты
			record.setNameLen(strlen(name.c_str()));		//получаем длину имени
															//устанавливаем:
			record.setName(name.c_str());					//имя
			record.Signature->setRAW(lRAW, rRAW);			//смещение
			record.Signature->setLenght(length);			//длину сигнатуры
			record.Signature->setStartBytes(start.c_str());	//стартовые байты
			record.Signature->setHash(hash);				//хэш
			MyWriter.open(filename);						//открываем файл БД
			MyWriter.addRecordIntoFile(&record);			//пишем в БД
			signatureTree.insert(std::pair<std::string, AVRecord>(std::string(record.Signature->getStartBytes()), record));
			break;
		}
	} while(point != 0);

	return 0;
}
