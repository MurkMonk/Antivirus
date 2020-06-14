#pragma once

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

//Zarija Podolski Nizhnic
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
	if ((extens.compare("Kasperski") == 0)) { return 1; }
	return 0;
}

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
	setlocale(LC_ALL, "rus");
	//создаем объекты
	AVDataBaseFileReader MyReader;
	AVDataBaseFileWriter MyWriter;//создаем объект класса-писателя для записи в БД бд
	char* filename = new char[256];

	std::cout << "\t\t*******Антивирус:Консольное приложение********" << std::endl << std::endl;
	while (true) {
		std::cout << "\nПожалуйста, введите путь к файлу антивирусной базы, с указанием самого файла:" << std::endl;
		std::cin >> filename;
		if (!Check_file_ext(filename))
		{
			std::cout << "\nЭто не файл антивирусной базы, введите его снова." << std::endl;
		}
		else break;
	}
	MyReader.open(filename);
	std::map<std::string, AVRecord>signatureTree; //создаем дерево сигнатур
	MyReader.readFromDataBase(&signatureTree);
	free(filename);
	//объявление переменных
	int point = 0;
	std::string watchPath;
	std::wstring scanPath;
	std::thread* bg = nullptr;
	std::string signature;
	size_t hash = 0;
	std::string name;
	std::string start;
	int16_t lRAW, rRAW, length;

	//создаем объекты классов
	DirScanner* Dirsc;
	Subject<std::string> DirStateWatcher;
	PEObjectFactory factory;
	ScanEngine scanner;
	AVRecord record = AVRecord();
	/*std::ifstream ifs;
	char* buf = new char[30];*/
	do {
		std::cout << "\nПожалуйста выберите из предложенного списка:" << std::endl;
		std::cout << "Введите 1 , чтобы сканировать директорию\n";
		std::cout << "Введите 2 , чтобы мониторить директорию\n";
		std::cout << "Введите 3 , чтобы добавить новую запись\n";
		std::cout << "Введите 0 , чтобы выйти\n";
		std::cin >> point;
		
		switch(point)
		{
		case 1: 
			std::cout << "Введите путь к папке: ";
			std::wcin >> scanPath;
			std::cout<<"\nПроцесс сканирования...."<<std::endl;
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
			std::cout << "Введите путь к папке: ";
			std::cin >> watchPath;
			factory = PEObjectFactory();
			scanner = ScanEngine();
			scanner.addBase(signatureTree);
			DirStateWatcher.attachObserver(&factory);
			factory.attachObserver(&scanner);
			bg = new std::thread(MyDirWatcher, std::ref(DirStateWatcher), watchPath.c_str());
			//bg->join();
			std::cout << "\nНаблюдатель установлен!" << std::endl<<std::endl;
			break;
		case 3:
			std::cout << "Введите имя сигнатуре: "; std::cin >> name;
			std::cout << "Введите смещение: "; std::cin >> lRAW >> rRAW;
			std::cout << "Введите длину сигнатуры: "; std::cin >> length;
			std::cout << "Введите сигнатуру: "; std::cin >> signature;

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
		//case 4:
		//	ifs.open("regex", std::ios::binary | std::ios::in);
		//	ifs.read(buf, 25);
		//	signature = std::string(buf);
		//	record.setNameLen(strlen(std::string("RegexDllTest").c_str()));		//получаем длину имени
		//													//устанавливаем:
		//	start = signature.substr(0, 8);
		//	record.setName(std::string("RegexDllTest").c_str());					//имя
		//	record.Signature->setRAW(5, 17);			//смещение
		//	record.Signature->setLenght(25);			//длину сигнатуры
		//	record.Signature->setStartBytes(start.c_str());	//стартовые байты
		//	record.Signature->setHash(getStringHash(signature));				//хэш
		//	MyWriter.open(filename);						//открываем файл бд
		//	MyWriter.addRecordIntoFile(&record);			//пишем в бд
		//	break;
		}
	} while(point != 0);
	

	return 0;
}

