#include <iostream>
#include <string>
#include <vector>
#include <bitset>
#include <sstream>

using namespace std;


/*
 * Splitting text into 32 bits blocks because
 * TEA use to encryption 32bits blocks
 */
vector<string> Split(const string& str, int splitLength) {
    int NumSubstrings = str.length() / splitLength;
    vector<string> ret;

    for (auto i = 0; i < NumSubstrings; i++)
    {
        ret.push_back(str.substr(i * splitLength, splitLength));
    }

    // If the number of bits is not multiple of 32 bits, add dots "." to last block
    // so every block has 32 bits
    if (str.length() % splitLength != 0)
    {
        int numberOfItemsToAdd = splitLength - str.substr(splitLength * NumSubstrings).size();
        string fill = "";
        for (int i = 0; i < numberOfItemsToAdd; i++)
        {
            fill += ".";
        }

        ret.push_back(str.substr(splitLength * NumSubstrings) + fill);

    }


    return ret;
}


/* encrypt
 *   Encrypt 64 bits with a 128 bit key using TEA
 *   From http://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
 * Arguments:
 *   v - array of two 32 bit uints to be encoded in place
 *   k - array of four 32 bit uints to act as key
 * Returns:
 *   v - encrypted result
 * Side effects:
 *   None
 */
void encrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i < 32; i++) {                       /* basic cycle start */
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;

}

/* decrypt
 *   Decrypt 64 bits with a 128 bit key using TEA
 *   From http://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
 * Arguments:
 *   v - array of two 32 bit uints to be decoded in place
 *   k - array of four 32 bit uints to act as key
 * Returns:
 *   v - decrypted result
 * Side effects:
 *   None
 */
void decrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up */ // 2 bloki 32 bit danych
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;

}

/*
 * Convert a plaintext to number
 * Plaintext -> binary representation -> uint32_t
 */
uint32_t convert (string plaintext){

    uint32_t block; //to return

    //
    std::string binaryPlaintext;
    for (std::size_t i = 0; i < plaintext.size(); ++i)
    {
        bitset<8> b(plaintext.c_str()[i]);
        binaryPlaintext+= b.to_string();
    }

    block = (uint32_t) stoi(binaryPlaintext, nullptr, 2);


    return block;
}

/*
 * Convert plaintext as number to text
 * uint32_t -> binary representation -> plaintext
 */
string reverseConvert (uint32_t block){

    string plaintext; //to return

    string binaryPlaintext = std::bitset< 32 >( block ).to_string();
    std::stringstream sstream(binaryPlaintext);
    int i =0;
    while(sstream.good())
    {
        std::bitset<8> bits;
        sstream >> bits;
        char c = char(bits.to_ulong());

        if(i<4) {
            plaintext += c;
            i++;
        }
    }


    return plaintext;
}

int main() {

    string s = "Hakuna Matata! What a wonderful phrase\n"
            "Hakuna Matata! Ain't no passing craze\n"
            "It means no worries for the rest of your days\n"
            "It's our problem-free philosophy\n"
            "Hakuna Matata!"; //Plaintext to encrypt

    cout << s.length() << endl;

    vector<string> splittedText = Split(s, 4);

    //Check if text is splitted correctly
    for (int i = 0; i < splittedText.size(); i++) {
        cout << splittedText[i] << endl;
    }

    //Encrypted text
    string encryptedText;
    //Decrypted full text
    string decryptedText;

    for (int j = 0; j < splittedText.size() - 1; j += 2) {

        uint32_t block1 = convert(splittedText[j]);
        uint32_t block2 = convert(splittedText[j + 1]);

        uint32_t blocks[2] = {block1, block2};
        uint32_t key[4] = {1423015205, 1963615285, 1693030209, 2293015211};

        cout << endl << "Plaintext: " << splittedText[j] << " " << splittedText[j + 1] << endl;
        cout << "Text as number: " << blocks[0] << " " << blocks[1] << endl;
        encrypt(blocks, key);
        encryptedText += reverseConvert(blocks[0]);
        encryptedText += reverseConvert(blocks[1]);
        cout << "Encrypted number: " << blocks[0] << " " << blocks[1] << endl;
        cout << "Encrypted text: " << reverseConvert(blocks[0]) << reverseConvert(blocks[1]) << endl;
        decrypt(blocks, key);
        cout << "Decrypted number: " << blocks[0] << " " << blocks[1] << endl;
        string plaintext = reverseConvert(blocks[0]) + reverseConvert(blocks[1]);
        cout << "Decrypted text: " << plaintext << endl;

        decryptedText += plaintext;
    }


    //Check if number of blocks is even
    //If not encrypt the last block with 32-bit block "...."
    if(splittedText.size() % 2)
    {

        uint32_t block1 = convert(splittedText[splittedText.size() - 1]);
        uint32_t block2 = convert("....");

        uint32_t blocks[2] = {block1, block2};
        uint32_t key[4] = {1423015205, 1963615285, 1693030209, 2293015211};

        cout << endl << "Plaintext: " << splittedText[splittedText.size() - 1] << " " << "...." << endl;
        cout << "Text as number: " << blocks[0] << " " << blocks[1] << endl;
        encrypt(blocks, key);
        encryptedText += reverseConvert(blocks[0]);
        encryptedText += reverseConvert(blocks[1]);
        cout << "Encrypted number: " << blocks[0] << " " << blocks[1] << endl;
        cout << "Encrypted text: " << reverseConvert(blocks[0]) << reverseConvert(blocks[1]) << endl;
        decrypt(blocks, key);
        cout << "Decrypted number: " << blocks[0] << " " << blocks[1] << endl;
        string plaintext = reverseConvert(blocks[0]) + reverseConvert(blocks[1]);
        cout << "Decrypted text: " << plaintext << endl;

        decryptedText += plaintext;
}

    cout << endl << "Encrypted full text: " << endl << encryptedText << endl;
    cout << endl << "Decrypted full text: " << endl << decryptedText << endl;

    return 0;
}
