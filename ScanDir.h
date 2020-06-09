#pragma once
#include "includes.h"
#include <filesystem>
#include <iostream>
#include <string>
#include <algorithm>
#include <fstream>
#include <vector>
#include <iterator>
#include "Subject.h"
#include <thread>

/*	ОБЪЯВЛЕНИЕ КЛАССА ДЛЯ СКАНИРОВАНИЯ ДИРЕКТОРИЙ 
*Осуществляет поиск PE-файлов в заданной директории
*Для поиска используются фукнкции из std::filesystem
*/
class DirScanner :public Subject<std::string> {
	std::wstring dir_name; // - путь до сканируемой папки

   //конструктор, для установки начальных значений
public:
	DirScanner(std::wstring Dir) {
		this->dir_name = Dir;

	}
	//Геттеры/Сеттеры
public:

	void setPathToFolder(std::wstring path)
	{ 
	
		this->dir_name = path;
	}
	std::wstring getPathToFolder() const{ return this->dir_name; }

	//сигнатуры функций

	void GetPE_from_Dir();


};
