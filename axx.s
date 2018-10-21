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

// AES-128/128 in ARM64 assembly
// 388 bytes

    .arch armv8-a
    .text

    .global E
    
// *****************************
// Multiplication over GF(2**8)
// *****************************
M:
    and      w10, w14, 0x80808080
    mov      w12, 27
    lsr      w8, w10, 7
    mul      w8, w8, w12
    eor      w10, w14, w10
    eor      w10, w8, w10, lsl 1
    ret

// *****************************
// B SubByte(B x);
// *****************************
S:
    str      lr, [sp, -16]!
    uxtb     w7, w13
    cbz      w7, SB3

    mov      w14, 1
    mov      w15, 0
    mov      x3, 0xFF
SB0:
    cmp      w15, 0
    ccmp     w14, w7, 0, eq
    bne      SB1
    mov      w14, 1
    mov      w15, 1
SB1:
    bl       M
    eor      w14, w14, w10
    uxtb     w14, w14
    subs     x3, x3, 1
    bne      SB0
    
    mov      w7, w14
    mov      x3, 4
SB2:
    lsr      w10, w14, 7
    orr      w14, w10, w14, lsl 1
    eor      w7, w7, w14
    subs     x3, x3, 1
    bne      SB2
SB3:
    mov      w10, 99
    eor      w7, w7, w10 
    bfxil    w13, w7, 0, 8
    ldr      lr, [sp], 16
    ret
    
// *****************************
// void E(void *s);
// *****************************
E:
    str      lr, [sp, -16]!
    sub      sp, sp, 32
    add      x1, sp, 16
    
    // copy plain text + master key to x
    // F(8)x[i]=((W*)s)[i];
    ldp      x5, x6, [x0]
    ldp      x7, x8, [x0, 16]
    stp      x5, x6, [sp]
    stp      x7, x8, [x1]
    
    // c = 1
    mov      w4, 1
L0:
    // AddRoundKey, 1st part of ExpandRoundKey
    // w=k[3];F(4)w=(w&-256)|S(w),w=R(w,8),((W*)s)[i]=x[i]^k[i];
    mov      x2, 0
    ldr      w13, [x1, 3*4]
L1:
    bl       S
    ror      w13, w13, 8
    ldr      w10, [sp, x2, lsl 2]
    ldr      w11, [x1, x2, lsl 2]
    eor      w10, w10, w11
    str      w10, [x0, x2, lsl 2]
    add      x2, x2, 1
    cmp      x2, 4
    bne      L1
    
    // AddRoundConstant, perform 2nd part of ExpandRoundKey
    // w=R(w,8)^c;F(4)w=k[i]^=w;
    eor      w13, w4, w13, ror 8
    mov      x2, xzr
L2:
    ldr      w10, [x1, x2, lsl 2]
    eor      w13, w13, w10
    str      w13, [x1, x2, lsl 2]
    add      x2, x2, 1
    cmp      x2, 4
    bne      L2
    
    // if round 11, stop
    // if(c==108)break;
    cmp      w4, 108
    beq      L5
    
    // update round constant
    // c=M(c);
    mov      w14, w4
    bl       M
    mov      w4, w10
    
    // SubBytes and ShiftRows
    // F(16)((B*)x)[(i%4)+(((i/4)-(i%4))%4)*4]=S(s[i]);
    mov      x2, xzr
L3:
    ldrb     w13, [x0, x2]
    bl       S
    and      w10, w2, 3
    lsr      w11, w2, 2
    sub      w11, w11, w10
    and      w11, w11, 3
    add      w10, w10, w11, lsl 2
    uxtb     w10, w10
    strb     w13, [sp, x10]
    add      x2, x2, 1
    cmp      x2, 16
    bne      L3
    
    // if (c != 108)
    cmp      w4, 108
    beq      L0
    
    // MixColumns
    // F(4)w=x[i],x[i]=R(w,8)^R(w,16)^R(w,24)^M(R(w,8)^w);
    mov      x2, xzr
L4:
    ldr      w13, [sp, x2, lsl 2]
    eor      w14, w13, w13, ror 8
    bl       M
    eor      w14, w10, w13, ror 8
    eor      w14, w14, w13, ror 16
    eor      w14, w14, w13, ror 24
    str      w14, [sp, x2, lsl 2]
    add      x2, x2, 1
    cmp      x2, 4
    bne      L4
    
    b        L0
L5:
    add      sp, sp, 32
    ldr      lr, [sp], 16
    ret
