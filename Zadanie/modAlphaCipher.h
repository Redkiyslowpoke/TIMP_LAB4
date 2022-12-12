/** @file
 * @author Воронин Н.А.
 * @date 11.12.2022
 * @copyright ИБСТ ПГУ
 * @brief Заголовочный файл проекта
 */
#pragma once
#include <iostream>
#include <algorithm>
#include <string>
#include <locale>
#include <codecvt>
/** @brief Шифрование методом маршрутной перестановки
 * @details Ключ устанавливается в конструкторе.
 * Для зашифровывания и расшифровывания предназначены методы encrypt и decrypt.
 */
class modAlphaCipher
{
private:
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> codec; ///<переменная для преобразования широких строк в обычные;
    int key; ///<ключ
public:
    modAlphaCipher()=delete; ///<запрет конструктора без параметров
    /**
     * @brief Конструктор
     * @param [in] skey Ключ. Не должен быть пустой строкой или отрицательным числом и содержать недопустимые символы.
     * Дробные числа автоматически преобразуются к целым.
     * @warning Недопустимыми символами считаются все символы кроме цифр
     * @throw string, если ключ пустой, отрицательный или содержит недопустимые символы
     */
    modAlphaCipher(const std::string& skey); ///<конструктор для установки ключа
    /**
     * @brief Зашифровывание
     * @param [in] open_text Открытый текст. Не должен быть пустой строкой.
     * @return Зашифрованная строка
     * @throw string, если текст пустой
     */
    std::string encrypt(const std::string& open_text); ///<функция зашифрования
    /**
     * @brief Расшифровывание
     * @param [in] cipher_text Зашифрованный текст. Не должен быть пустой строкой
     * @return Расшифрованная строка
     * @throw string, если текст пустой
     */
    std::string decrypt(const std::string& cipher_text); ///<функция расшифрования
    
};