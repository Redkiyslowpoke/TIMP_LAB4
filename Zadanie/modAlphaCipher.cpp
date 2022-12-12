/** @file
 * @author Воронин Н.А.
 * @date 11.12.2022
 * @copyright ИБСТ ПГУ
 * @brief Модуль реализации методов класса modAlphaCipher
 */
#include "modAlphaCipher.h"
#include <iostream>
modAlphaCipher::modAlphaCipher(const std::string& skey)
{
    if (skey.empty())
        throw std::string("Empty key");
    int res = stoi(skey);
    if (res < 0) throw std::string("Negative value");
    if (res == 0) throw std::string("0 can't be a key");
    key = res;
}
std::string modAlphaCipher::encrypt(const std::string& open_text)
{
    if (open_text.empty())
        throw std::string("Empty text");
    std::wstring wopen_text = codec.from_bytes(open_text);
    std::wstring c = L"";
    int poz = key - 1;
    while (poz >= 0) {
        for (uint i = poz; i < wopen_text.size(); i = i + key) {
            c += wopen_text[i];
        }
        poz -= 1;
    }
    std::string s = codec.to_bytes(c);
    return s;
}
std::string modAlphaCipher::decrypt(const std::string& cipher_text)
{
    if (cipher_text.empty())
        throw std::string("Empty text");
    std::wstring wcipher_text = codec.from_bytes(cipher_text);
    std::wstring d = wcipher_text;
    reverse(d.begin(), d.end());
    int poz = 0;
    int strk = d.size()/key;
    std::wstring last = L"";
    int ost = d.size()%key;
    for (int i = 0; i < ost ; i++) {
        last += d[poz];
        d.erase(poz,1);
        poz += strk;
    }
    poz = strk - 1;
    std::wstring rez = L"";
    while (poz >= 0) {
        for (uint i = poz; i < d.size(); i = i + strk) {
            rez += d[i];
        }
        poz -= 1;
    }
    std::string s = codec.to_bytes(rez+last);
    return s;
}
