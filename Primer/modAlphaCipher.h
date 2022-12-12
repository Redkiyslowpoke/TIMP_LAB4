/** @file
 * @author Воронин Н.А.
 * @date 11.12.2022
 * @copyright ИБСТ ПГУ
 * @brief Заголовочный файл проекта
 */
#pragma once
#include <stdexcept>
#include <vector>
#include <string>
#include <map>
#include <locale>
#include <codecvt>
/** @brief Шифрование методом Гронсфельда
 * @details Ключ устанавливается в конструкторе.
 * Для зашифровывания и расшифровывания предназначены методы encrypt и decrypt.
 * @warning Реализация только для русского языка
 */
class modAlphaCipher
{
private:
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> codec; ///<переменная для преобразования широких строк в обычные;
    std::wstring numAlpha =
        L"АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"; ///<алфавит по порядку
    std::map <wchar_t,int> alphaNum; ///<ассоциативный массив "номер по символу"
    std::vector <int> key; ///<ключ
    /**
     * @brief Преобразование строка-вектор
     * @param [in] s Строка из символов
     * @return Вектор числовых значений, соответствующих символам
     */
    std::vector<int> convert(const std::string& s); ///<преобразование строка-вектор
    /**
     * @brief Преобразование вектор-строка
     * @param [in] v Вектор числовых значений
     * @return Строка из символов, соответствующих числовым значениям
     */
    std::string convert(const std::vector<int>& v); ///<преобразование вектор-строка
    /**
     * @brief Проверка и преобразование ключа
     * @details Ключ проверяется на наличие запрещённых символов и пустоту и преобразуется.
     * Строчные буквы преобразуются в заглавные
     * @warning Запрещёнными символами считаются все символы кроме букв русского языка
     * @param [in] s Строка с введёным ключом
     * @return Строка с преобразованным ключом
     * @throw cipher_error, если ключ пустой, слабый или имеет недопустимые символы
     */
    std::string getValidKey(const std::string & s); ///<проверка и преобразование ключа
    /**
     * @brief Проверка и преобразование нормального текста
     * @details Текст проверяется на пустоту и преобразуется.
     * Строчные буквы преобразуются в заглавные, запрещённые символы удаляются из текста
     * @warning Запрещёнными символами считаются все символы кроме букв русского языка
     * @param [in] s Строка с введёным текстом
     * @return Строка с преобразованным текстом
     * @throw cipher_error, если текст пустой
     */
    std::string getValidOpenText(const std::string & s); ///<проверка и преобразование нормального текста
    /**
     * @brief Проверка зашифрованного текста
     * @details Текст проверяется на пустоту и наличие запрещённых символов.
     * @warning Запрещёнными символами считаются все символы кроме букв русского языка
     * @param [in] s Строка с введёным текстом
     * @return Строка с проверенным текстом
     * @throw cipher_error, если текст пустой или содержит запрещённые символы
     */
    std::string getValidCipherText(const std::string & s); ///<проверка зашифрованного текста
public:
    modAlphaCipher()=delete; ///<запрет конструктора без параметров
    /**
     * @brief Конструктор
     * @param [in] skey Ключ. Не должен быть пустой строкой и содержать недопустимые символы.
     * Строчные символы автоматически преобразуются к прописным.
     * @warning Запрещёнными символами считаются все символы кроме букв русского языка
     * @throw cipher_error, если ключ пустой или содержит запрещённые символы
     */
    modAlphaCipher(const std::string& skey); ///<конструктор для установки ключа
    /**
     * @brief Зашифровывание
     * @param [in] open_text Открытый текст. Не должен быть пустой строкой.
     * Строчные символы автоматически преобразуются к прописным.
     * Все не-буквы удаляются
     * @return Зашифрованная строка
     * @throw cipher_error, если текст пустой
     */
    std::string encrypt(const std::string& open_text); ///<функция зашифрования
    /**
     * @brief Расшифровывание
     * @param [in] cipher_text Зашифрованный текст. Не должен быть пустой строкой и содержать недопустимые символы.
     * @warning Запрещёнными символами считаются все символы кроме букв русского языка
     * @return Расшифрованная строка
     * @throw cipher_error, если текст пустой или содержит запрещённые символы
     */
    std::string decrypt(const std::string& cipher_text); ///<функция расшифрования
};
/** @brief Созданное исключение
 * @details Создано для отличия программных исключений от исключений, возбужденных модулем.
 */
class cipher_error : public std::invalid_argument
{
public:
    explicit cipher_error (const char* what_arg):std::invalid_argument(what_arg) {} ///<ошибка,возвращающая символ
    explicit cipher_error (const std::string& what_arg):std::invalid_argument(what_arg) {} ///<ошибка,возвращающая строку
};
