/**
  This is free and unencumbered software released into the public domain.

  Anyone is free to copy, modify, publish, use, compile, sell, or
  distribute this software, either in source code form or as a compiled
  binary, for any purpose, commercial or non-commercial, and by any
  means.

  In jurisdictions that recognize copyright laws, the author or authors
  of this software dedicate any and all copyright interest in the
  software to the public domain. We make this dedication for the benefit
  of the public at large and to the detriment of our heirs and
  successors. We intend this dedication to be an overt act of
  relinquishment in perpetuity of all present and future rights to this
  software under copyright law.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
  OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
  ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
  OTHER DEALINGS IN THE SOFTWARE.

  For more information, please refer to <http://unlicense.org/> */

// Test unit for AES-256 ECB mode
// Odzhan

#include <stdio.h>
#include <string.h>
#include <stdint.h>

void E(void*);

void bin2hex(char *s, void *p, int len) {
    int i;
    printf("%-10s : ", s);
    for (i=0; i<len; i++) {
      printf ("%02x ", ((uint8_t*)p)[i]);
    }
    printf("\n");
}

uint8_t aes256_tv[]=
{ 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 
  0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89};

int main (void)
{
  int     i, equ;
  struct {
    uint8_t s[16]; // 128-bit block
    uint8_t k[32]; // 256-bit key
  } x;
  
  puts ("\n**** AES-256 ECB Test ****\n");
  
  for(i=0;i<16;i++) x.s[i]=i*16+i;
  for(i=0;i<32;i++) x.k[i]=i;
  
  E(&x);                     // encrypt
    
  equ=(memcmp(x.s, aes256_tv, 16)==0);
    
  bin2hex("key", x.k, 32);
  bin2hex("cipher", x.s, 16);
    
  printf("AES-256 ECB: %s\n\n", equ ? "OK" : "FAILED");
      
  return 0;
}
