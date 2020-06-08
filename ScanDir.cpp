#pragma once
#include "pch.h"
#include "ScanDir.h"
#include <iostream>
#include <filesystem>
#include "FileWatcher.h"
#include <thread>

//Podolski
 void DirScanner::GetPE_from_Dir()
{

	for (auto &file : std::filesystem::recursive_directory_iterator(dir_name))
	{

		if (std::filesystem::is_regular_file(file.path()) && ((file.path().extension() == ".exe") || (file.path().extension() == ".dll") || (file.path().extension() == ".ocx") || (file.path().extension() == ".sys") || (file.path().extension() == ".scr") || (file.path().extension() == ".drv") || (file.path().extension() == ".cpl") || (file.path().extension() == ".msi")))
		{
			this->setState(file.path().u8string());
		}
	}
}
