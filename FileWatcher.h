#ifndef FILEWATCHER_H
#define FILEWATCHER_H

#include <filesystem>
#include <chrono>
#include <thread>
#include <unordered_map>
#include <string>
#include <functional>
#include "Subject.h"

/*	ОБЪЯВЛЕНИЕ КЛАССА ДЛЯ ОТСЛЕЖИВАНИЯ ИЗМЕНЕНИЙ В ДИРЕКТОРИЯХ
*Осуществляет отслеживание измененний в указанной директории и сообщает об этом
*Отслеживаются два параметра: Created и Modified для файла
Zarija
*/

enum FileStatus {created, modified};

class FileWatcher:public Subject<std::string> {
private:
	//Создадим unordered_map для хранения пути до файла и времени ее изменения
	std::unordered_map<std::string, std::filesystem::file_time_type> paths_;
	bool IsRunning = true;

	//ищем ключ в unordered_map
	bool contains(const std::string &key) {
		auto map_element = paths_.find(key);
		return map_element != paths_.end();
	}

public:
	//путь до отслеживаемой папки
    std::string path_to_watch;
    // Временной интервал, по прошествию которого мы проверяем указанную папку на изменения
    std::chrono::duration<int, std::milli> delay;

    // учет файлов из каталога и их время последнего изменения
	FileWatcher(std::string path_to_watch, std::chrono::duration<int, std::milli> delay);
    // запускает отслеживание указанной директории
	void start(Subject<std::string>&,const std::function<void(std::string, FileStatus, Subject<std::string>&)> &action);
};
#endif
