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
  
#define F(n)for(i=0;i<n;i++)
typedef unsigned char B;
typedef unsigned int W;
// Multiplication over GF(2**8)
#define M(x)(((x)<<1)^((((x)>>7)&1)*0x1b))
// SubByte
B S(B x) {
    B i,y,c;
    if(x) {
      for(c=i=0,y=1;--i;y=(!c&&y==x)?c=1:y,y^=M(y));
      x=y;F(4)x^=y=(y<<1)|(y>>7);
    }
    return x^99;
}
#define K_LEN 16 // 128-bit
void E(B *s) {
    B a,b,c,d,i,t,x[32],rc=1,*k=&x[16];
    
    // copy 128-bit plain text + 128-bit master key to x
    F(32)x[i]=s[i];

    for(;;) {
      // AddRoundKey
      F(16)s[i]=x[i]^k[i];
      // if round 11, stop
      if(rc==108)break;
      // ExpandKey
      k[0]^=S(k[13])^rc,k[1]^=S(k[14]),
      k[2]^=S(k[15]),k[3]^=S(k[12]);
      for(i=4;i<16;i+=4)
        k[i+0]^=k[i-4],k[i+1]^=k[i-3],
        k[i+2]^=k[i-2],k[i+3]^=k[i-1];
      // update round constant
      rc=M(rc);
      // SubBytes and ShiftRows
      F(16)x[(i%4)+(((W)(i/4)-(i%4))%4)*4]=S(s[i]);
      // if not round 11
      if(rc!=108)
        // MixColumns
        for(i=0;i<16;i+=4)
          a=x[i],b=x[i+1],c=x[i+2],d=x[i+3],t=a^b^c^d,
          x[i+0]^=t^M(a^b),x[i+1]^=t^M(b^c),
          x[i+2]^=t^M(c^d),x[i+3]^=t^M(d^a);
    }
}

#ifdef CTR
// encrypt using Counter (CTR) mode
void encrypt(B l, B*c, B*p, B*k) {
    B i,r,t[K_LEN+16];

    // copy master key to local buffer
    F(K_LEN)t[i+16]=k[i];

    while(l) {
      // copy counter+nonce to local buffer
      F(16)t[i]=c[i];
      // encrypt t
      E(t);
      // XOR plaintext with ciphertext
      r=l>16?16:l;
      F(r)p[i]^=t[i];
      // update length + position
      l-=r;p+=r;
      // update counter
      for(i=16;i>0;i--)
        if(++c[i-1])break;
    }
}
#endif
