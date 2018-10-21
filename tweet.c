// AES-128 in C
#define R(v)(((v)>>8)|((v)<<24))
#define F(n)for(i=0;i<n;i++)
typedef unsigned char B;typedef unsigned W;W M(W x){W t=x&0x80808080;return((x^t)*2)^((t>>7)*27);}B S(B x){B i,y,c;if(x){for(c=i=0,y=1;--i;y=(!c&&y==x)?c=1:y,y^=M(y));x=y;F(4)x^=y=(y+y)|(y>>7);}return x^99;}void E(B*s){W i,w,x[8],c=1,*k=(W*)&x[4];F(8)x[i]=((W*)s)[i];for(;;){w=k[3];F(4)w=(w&-256)|S(w),w=R(w),((W*)s)[i]=x[i]^k[i];w=R(w)^c;F(4)w=k[i]^=w;if(c==108)break;c=M(c);F(16)((B*)x)[(i%4)+(((i/4)-(i%4))%4)*4]=S(s[i]);if(c!=108)F(4)w=x[i],x[i]=R(w)^R(R(w))^R(R(R(w)))^M(R(w)^w);}}