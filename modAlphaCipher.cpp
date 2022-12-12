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
    for (unsigned i=0; i<numAlpha.size(); i++) {
        alphaNum[numAlpha[i]]=i;
        
    }
    key = convert(getValidKey(skey));
}
std::string modAlphaCipher::encrypt(const std::string& open_text)
{
    std::vector<int> work = convert(getValidOpenText(open_text));
    for(unsigned i=0; i < work.size(); i++) {
        work[i] = (work[i] + key[i % key.size()]) % alphaNum.size();
    }
    return convert(work);
}
std::string modAlphaCipher::decrypt(const std::string& cipher_text)
{
    std::vector<int> work = convert(getValidCipherText(cipher_text));
    for(unsigned i=0; i < work.size(); i++) {
        work[i] = (work[i] + alphaNum.size() - key[i % key.size()]) % alphaNum.size();
    }
    return convert(work);
} 
inline std::vector<int> modAlphaCipher::convert(const std::string& s)
{
    std::wstring ws = codec.from_bytes(s);
    std::vector<int> result;
    for(auto c:ws) {
        result.push_back(alphaNum[c]);
    }
    return result;
}
inline std::string modAlphaCipher::convert(const std::vector<int>& v)
{
    std::wstring wresult;
    for(auto i:v) {
        wresult.push_back(numAlpha[i]);
    }
    std::string result = codec.to_bytes(wresult);
    return result;
}
inline std::string modAlphaCipher::getValidKey(const std::string & s)
{
    if (s.empty())
        throw cipher_error("Empty key");
    std::wstring tmp = codec.from_bytes(s);
    for (wchar_t & wc:tmp) {
        if (!((wc>1039 and wc<1104) or wc ==1025 or wc ==1105))
            throw cipher_error(std::string("Invalid key "));
        if (wc>1071 and wc<1104)
            wc = wc - 32;
        else if(wc ==1105)
            wc = wc - 80;
    }
    if (tmp == std::wstring(tmp.size(),L'А'))
        throw cipher_error(std::string("Weak key"));
    std::string tmps = codec.to_bytes(tmp);
    return tmps;
}
inline std::string modAlphaCipher::getValidOpenText(const std::string & s)
{
    std::wstring ws = codec.from_bytes(s);
    std::wstring tmp;
    for (auto wc:ws) {
        if ((wc>1039 and wc<1104) or wc ==1025 or wc ==1105) {
            if (wc>1071 and wc<1104)
                tmp.push_back(wc - 32);
            else if(wc ==1105)
                tmp.push_back(wc - 80);
            else
                tmp.push_back(wc);
        }
    }
    if (tmp.empty())
        throw cipher_error("Empty open text");
    std::string tmps = codec.to_bytes(tmp);
    return tmps;
}
inline std::string modAlphaCipher::getValidCipherText(const std::string & s)
{
    if (s.empty())
        throw cipher_error("Empty cipher text");
    std::wstring ws = codec.from_bytes(s);
    for (auto c:ws) {
        if ((c>1071 and c<1104) or c ==1105)
            throw cipher_error(std::string("Invalid cipher text "));
    }
    return s;
};