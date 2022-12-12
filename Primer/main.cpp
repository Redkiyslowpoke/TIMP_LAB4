/** @file
 * @author Воронин Н.А.
 * @date 11.12.2022
 * @copyright ИБСТ ПГУ
 * @brief Главный модуль проекта
 */
#include <iostream>
#include <cctype>
#include "modAlphaCipher.h"
using namespace std;
int main()
{
    try {
        string key;
        string text;
        unsigned op;
        cout<<"Cipher ready. Input key: ";
        cin>>key;
        cout<<"Key loaded\n";
        modAlphaCipher cipher(key);
        do {
            cout<<"Cipher ready. Input operation (0-exit, 1-encrypt, 2-decrypt): ";
            cin>>op;
            if (op > 2) {
                cout<<"Illegal operation\n";
            } else if (op >0) {
                cout<<"Cipher ready. Input text: ";
                cin.ignore();
                getline(cin, text);
                if (op==1) {
                    cout<<"Encrypted text: "<<cipher.encrypt(text)<<endl;
                } else {
                    cout<<"Decrypted text: "<<cipher.decrypt(text)<<endl;
                }
            }
        } while (op!=0);
    } catch (const string e) {
        cerr<<"Error: "<< e <<endl;
    } 
    return 0;
}
