#pragma once

#include "includes.h"
#include<windows.h>
#include <codecvt>


/*	ОБЪЯВЛЕНИЕ КЛАССОВ ДЛЯ ХРАНЕНИЯ ИНФОРМАЦИИ О СИГНАТУРАХ И О ЗАПИСАХ БД
Zarija
*/

/* Класс записи о вирусе

 Структура записи :
 	 *	Название вируса;
	 *	длина имени;
	 *	Сигнатура[
		 *	Смещение сигнатуры;
			 *	хэш;
			 *	длина сигнатуры;
			 *	стартовые байты сигнатуры;];
	 *	тип файла, в котором может находиться сигнатура;
 */
 class AVRecord{
	 char* Name; // - название вируса
	 unsigned char NameLen; // - длина имени
 public: 
	 /* Класс сигнатуры:
	 *	Смещение сигнатуры;
	 *	хэш;
	 *	длина сигнатуры;
	 *	стартовые байты сигнатуры;
	 */
	 class AVSignature{
		 friend class AVRecord;
		 int16_t lRAW; // - Смещение сигнатуры
		 int16_t rRAW; // - Смещение сигнатуры
		 size_t Hash; // -  хэш
		 int16_t Lenght; // - длина сигнатуры
		 char* StartByte; // - стартовые байты сигнатуры
		 //конструктор по умолчанию (зануляющий)
	 public: AVSignature(){
				 this->lRAW = 0; //зануляем смещение
				 this->rRAW = 0; //зануляем смещение
				 this->Lenght = 0; // зануляем длину сигнатуры
				 this->Hash = 0; //зануляем хэш
				 this->StartByte = new char[8];
				 memset(this->StartByte, 0, 8 * sizeof(char)); //зануляем стартовые байты
	 }
			 //Геттеры/Сеттеры
	 public:
		 void setRAW(int l, int r) { this->lRAW = l; this->rRAW = r; } //устанавливаем смещение
		 int16_t* getRAW()const { int16_t RAW[]={ lRAW, rRAW }; return RAW; }	//получаем смещение
		 void setLenght(int16_t number) { this->Lenght = number; }
		 int16_t getLenght() { return this->Lenght; }
		 void setHash(size_t NewHash) { this->Hash = NewHash; }
		 size_t getHash()  { return this->Hash; }
		 void setStartBytes(const char* str)
		 {
			 char* buf = new char[9];
			 strncpy(buf, str, 8);
			 buf[8] = '\0';
			 strcpy(this->StartByte,buf);
		 }
		 char* getStartBytes() { return this->StartByte; }

	 }; AVSignature *Signature;
 public:
	 char* FileType; //-тип файла

	//конструктор, для установки начальных нулей
public:	
	AVRecord(){
		size_t len = 50;
		this->Name = new char[len]; 
		memset(this->Name, 0, sizeof(char) * len); 
		this->NameLen = 0; 
		this->FileType = new char[10];
		memset(this->FileType, 0, sizeof(char)*10);
		Signature = new AVSignature();
	}
	AVRecord(char* name) {
		strcpy(this->Name, name);
		this->NameLen = strlen(this->Name);
		this->FileType = new char[10];
		memset(this->FileType, 0, sizeof(char) * 10);
		Signature = new AVSignature();
	}
	//Геттеры/Сеттеры
 public:
	 void setNameLen(int number) { this->NameLen = number; }
	 unsigned char getNameLen()const { return this->NameLen; }
	 void setName(const char*name) { strcpy(this->Name, name); this->Name[NameLen] = '\0'; }
	 char* getName()const { return this->Name; }
	
	 //! Выделение памяти под имя
	 void allocName(unsigned char NameLen){
		if (this->Name == NULL){
			this->NameLen = NameLen;
			this->Name = new char[this->NameLen + 1];
			memset(this->Name, 0, this->NameLen + 1);
		}
	}
 
 };
