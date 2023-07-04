#include "cryptlib.h"
#include "rijndael.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"

int read_file(const char* file_path, unsigned char** dataptr, size_t* sizeptr) {
  FILE* fp = NULL;
  fp = fopen(file_path, "rb");
  if (fp == NULL) {
    fprintf(stderr, "[M]open file(%s) failed", file_path);
    return 1;
  }

  fseek(fp, 0, SEEK_END);
  *sizeptr = ftell(fp);
  *dataptr = (unsigned char*)malloc(sizeof(unsigned char) * (*sizeptr));

  fseek(fp, 0, SEEK_SET);
  fread(*dataptr, 1, *sizeptr, fp);
  fclose(fp);

  return 0;
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    fprintf(stderr, "usage:\n  encryptor need model_path \n");
    return 1;
  }
  auto model_path = argv[1];
  unsigned char* plain = NULL;
  size_t plain_len = 0;
  int ret = read_file(model_path, &plain, &plain_len);
  if (!ret) {
      return ret;
  }
  using namespace CryptoPP;

  AutoSeededRandomPool prng;
  HexEncoder encoder(new FileSink(std::cout));

  SecByteBlock key(AES::DEFAULT_KEYLENGTH);
  SecByteBlock iv(AES::BLOCKSIZE);

  prng.GenerateBlock(key, key.size());
  prng.GenerateBlock(iv, iv.size());

  // std::string plain = "CBC Mode Test:Hello!";
  std::string cipher, recovered;

  // std::cout << "plain text: " << plain << std::endl;

  /*********************************\
  \*********************************/

  try
  {
      CBC_Mode< AES >::Encryption e;
      e.SetKeyWithIV(key, key.size(), iv);

      StringSource s(plain, true,
          new StreamTransformationFilter(e,
              new StringSink(cipher)
          ) // StreamTransformationFilter
      ); // StringSource
  }
  catch (const Exception& e)
  {
      std::cerr << e.what() << std::endl;
      exit(1);
  }

  /*********************************\
  \*********************************/

  std::cout << "key: ";
  encoder.Put(key, key.size());
  encoder.MessageEnd();
  std::cout << std::endl;

  std::cout << "iv: ";
  encoder.Put(iv, iv.size());
  encoder.MessageEnd();
  std::cout << std::endl;

  std::cout << "cipher text: ";
  encoder.Put((const byte*)&cipher[0], cipher.size());
  encoder.MessageEnd();
  std::cout << std::endl;

  /*********************************\
  \*********************************/

  try
  {
      CBC_Mode< AES >::Decryption d;
      d.SetKeyWithIV(key, key.size(), iv);

      StringSource s(cipher, true,
          new StreamTransformationFilter(d,
              new StringSink(recovered)
          ) // StreamTransformationFilter
      ); // StringSource

      std::cout << "recovered text: " << recovered << std::endl;
  }
  catch (const Exception& e)
  {
      std::cerr << e.what() << std::endl;
      exit(1);
  }

  return 0;
}
