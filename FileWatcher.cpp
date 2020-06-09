#pragma once
#include "pch.h"
#include "FileWatcher.h"

//Nizhnic
void FileWatcher::start(Subject<std::string>&subj,const std::function<void(std::string, FileStatus, Subject<std::string>&)> &action) {
	while (IsRunning) {
		// задержа считывания
		std::this_thread::sleep_for(delay);

		// перебираем файлы в директории
		for (auto &file : std::filesystem::recursive_directory_iterator(path_to_watch))
		{ //записываем дату последнего изменения каждого файла
			auto current_file_last_write_time = std::filesystem::last_write_time(file);

			// если в unordered_map не найден указанный файл 
			if (!contains(file.path().string()))
			{
				//добавляем его в список файлов директории
				paths_[file.path().string()] = current_file_last_write_time;
				action(file.path().string(), FileStatus::created,subj);
				
			}// если файл изменен
			else {
				if (paths_[file.path().string()] != current_file_last_write_time) {
					paths_[file.path().string()] = current_file_last_write_time;
					action(file.path().string(), FileStatus::modified,subj);
				}
			}
		}
	}
}

FileWatcher::FileWatcher(std::string path_to_watch, std::chrono::duration<int, std::milli> delay) : path_to_watch{ path_to_watch }, delay{ delay }
{
	//заполняем unordered_map
	for (auto &file : std::filesystem::recursive_directory_iterator(path_to_watch)) {
		paths_[file.path().string()] = std::filesystem::last_write_time(file);
	}
}
