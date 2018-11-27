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
  
#define R(v,n)(((v)>>(n))|((v)<<(32-(n))))
#define F(n)for(i=0;i<n;i++)
typedef unsigned char B;
typedef unsigned int W;
// Multiplication over GF(2**8)
W M(W x){
    W t=x&0x80808080;
    return((x^t)*2)^((t>>7)*27);
}
// SubByte
B S(B x){
    B i,y,c;
    if(x){
      for(c=i=0,y=1;--i;y=(!c&&y==x)?c=1:y,y^=M(y));
      x=y;F(4)x^=y=(y<<1)|(y>>7);
    }
    return x^99;
}
#ifndef AES256
#define K_LEN 16 // 128-bit
void E(B *s){
    W i,w,x[8],c=1,*k=(W*)&x[4];

    // copy 128-bit plain text + 128-bit master key to x
    F(8)x[i]=((W*)s)[i];

    for(;;){
      // AddRoundKey, 1st part of ExpandKey
      w=k[3];F(4)w=(w&-256)|S(w),w=R(w,8),((W*)s)[i]=x[i]^k[i];
      // AddConstant, 2nd part of ExpandKey
      w=R(w,8)^c;F(4)w=k[i]^=w;
      // if round 11, stop
      if(c==108)break; 
      // update constant
      c=M(c);
      // SubBytes and ShiftRows
      F(16)((B*)x)[(i%4)+(((i/4)-(i%4))%4)*4]=S(s[i]);
      // if not round 11, MixColumns
      if(c!=108)
        F(4)w=x[i],x[i]=R(w,8)^R(w,16)^R(w,24)^M(R(w,8)^w);
    }
}
#else
#define K_LEN 32 // 256-bit
void E(B *s) {
    W i,r=0,w,x[12],c=1,*k=(W*)&x[4];

    // copy 128-bit plain text + 256-bit master key to x
    F(12)x[i]=((W*)s)[i];

    for(;;) {
      // 1st part of ExpandKey
      w=k[r?3:7];
      F(4)w=(w&-256)|S(w),w=R(w,8); 
      // AddConstant, update constant
      if(!r)w=R(w,8)^c,c=M(c);
      // AddRoundKey, 2nd part of ExpandKey
      F(4)((W*)s)[i]=x[i]^k[r*4+i], w=k[r*4+i]^=w;
      // if round 15, stop
      if(c==27) break;
      r=(r+1)&1;
      // SubBytes and ShiftRows
      F(16)((B*)x)[(i%4)+(((i/4)-(i%4))%4)*4]=S(s[i]);
      // if not round 15, MixColumns    
      if((c!=128) | r)
        F(4)w=x[i],x[i]=R(w,8)^R(w,16)^R(w,24)^M(R(w,8)^w);
    }
}
#endif

#ifdef CTR
// encrypt using Counter (CTR) mode
void encrypt(W l, B*c, B*p, B*k){
    W i,r;
    B t[K_LEN+16];

    // copy master key to local buffer
    F(K_LEN)t[i+16]=k[i];

    while(l){
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
