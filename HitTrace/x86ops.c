/*

  Copyright (c) 2014-2015 Samuel Lidén Borell <samuel@kodafritt.se>
 
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
  
  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.
  
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.

*/

#include "x86ops.h"
#include <stdio.h>

typedef unsigned char BYTE;

//#define ILLEGAL_INSTR_SIZE 1
#define ILLEGAL_INSTR_SIZE 255

/*#define OPND_BW  0x10*/
#define OPND_WD  0x20 /* 16/32-bit */
#define OPND_PP  0x30 /* 16/32-bit (although some web page says 32/48-bit) */
#define ADDR_WD  0x40 /* 16/32-bit */
#define OPNDADDRMASK 0x70
#define MODRM 0x80
#define ILLEGAL    0xF0
#define PREFIX     0xF1
#define TWOBYTE    0xF2
#define MULTI      0xF3
static const unsigned char opinfos[256] = {
    /* 0x00 - 0x0F */
    1|MODRM,/* 0: ADD modrm8 */
    1|MODRM,/* 1: ADD modrm16/32 */
    1|MODRM,/* 2: ADD modrm8 reversed */
    1|MODRM,/* 3: ADD modrm16/32 reversed */
    1+1,    /* 4: ADD AL, imm8 */
    1|OPND_WD,/* 5: ADD, EAX, imm16/32 */
    1,      /* 6: PUSH ES */
    1,      /* 7: POP ES */
    1|MODRM,/* 8: OR modrm8 */
    1|MODRM,/* 9: OR modrm16/32 */
    1|MODRM,/* A: OR modrm8 reversed */
    1|MODRM,/* B: OR modrm16/32 reversed */
    1+1,    /* C: OR AL, imm8 */
    1|OPND_WD,/* D: OR, EAX, imm16/32 */
    1,      /* E: PUSH CS */
    TWOBYTE,/* F: two byte instruction */
    
    /* 0x10 - 0x1F */
    1|MODRM,/* 0: ADC modrm8 */
    1|MODRM,/* 1: ADC modrm16/32 */
    1|MODRM,/* 2: ADC modrm8 reversed */
    1|MODRM,/* 3: ADC modrm16/32 reversed */
    1+1,    /* 4: ADC AL, imm8 */
    1|OPND_WD,/* 5: ADC, EAX, imm16/32 */
    1,      /* 6: PUSH SS */
    1,      /* 7: POP SS */
    1|MODRM,/* 8: SBB modrm8 */
    1|MODRM,/* 9: SBB modrm16/32 */
    1|MODRM,/* A: SBB modrm8 reversed */
    1|MODRM,/* B: SBB modrm16/32 reversed */
    1+1,    /* C: SBB AL, imm8 */
    1|OPND_WD,/* D: SBB, EAX, imm16/32 */
    1,      /* E: PUSH DS */
    1,      /* F: POP DS */
    
    /* 0x20 - 0x2F */
    1|MODRM,/* 0: AND modrm8 */
    1|MODRM,/* 1: AND modrm16/32 */
    1|MODRM,/* 2: AND modrm8 reversed */
    1|MODRM,/* 3: AND modrm16/32 reversed */
    1+1,    /* 4: AND AL, imm8 */
    1|OPND_WD,/* 5: AND, EAX, imm16/32 */
    PREFIX, /* 6: prefix DS: */
    1,      /* 7: DAA */
    1|MODRM,/* 8: SUB modrm8 */
    1|MODRM,/* 9: SUB modrm16/32 */
    1|MODRM,/* A: SUB modrm8 reversed */
    1|MODRM,/* B: SUB modrm16/32 reversed */
    1+1,    /* C: SUB AL, imm8 */
    1|OPND_WD,/* D: SUB, EAX, imm16/32 */
    PREFIX, /* E: prefix CS: */
    1,      /* F: DAS */
    
    /* 0x30 - 0x3F */
    1|MODRM,/* 0: XOR modrm8 */
    1|MODRM,/* 1: XOR modrm16/32 */
    1|MODRM,/* 2: XOR modrm8 reversed */
    1|MODRM,/* 3: XOR modrm16/32 reversed */
    1+1,    /* 4: XOR AL, imm8 */
    1|OPND_WD,/* 5: XOR, EAX, imm16/32 */
    PREFIX, /* 6: prefix SS: */
    1,      /* 7: AAA */
    1|MODRM,/* 8: CMP modrm8 */
    1|MODRM,/* 9: CMP modrm16/32 */
    1|MODRM,/* A: CMP modrm8 reversed */
    1|MODRM,/* B: CMP modrm16/32 reversed */
    1+1,    /* C: CMP AL, imm8 */
    1|OPND_WD,/* D: CMP, EAX, imm16/32 */
    PREFIX, /* E: prefix DS: */
    1,      /* F: AAS */
    
    /* 0x40 - 0x4F */
    1,      /* 0: INC EAX */
    1,      /* 1: INC ECX */
    1,      /* 2: INC EDX */
    1,      /* 3: INC EBX */
    1,      /* 4: INC ESP */
    1,      /* 5: INC EBP */
    1,      /* 6: INC ESI */
    1,      /* 7: INC EDI */
    1,      /* 8: DEC EAX */
    1,      /* 9: DEC ECX */
    1,      /* A: DEC EDX */
    1,      /* B: DEC EBX */
    1,      /* C: DEC ESP */
    1,      /* D: DEC EBP */
    1,      /* E: DEC ESI */
    1,      /* F: DEC EDI */
    
    /* 0x50 - 0x5F */
    1,      /* 0: PUSH EAX */
    1,      /* 1: PUSH ECX */
    1,      /* 2: PUSH EDX */
    1,      /* 3: PUSH EBX */
    1,      /* 4: PUSH ESP */
    1,      /* 5: PUSH EBP */
    1,      /* 6: PUSH ESI */
    1,      /* 7: PUSH EDI */
    1,      /* 8: POP EAX */
    1,      /* 9: POP ECX */
    1,      /* A: POP EDX */
    1,      /* B: POP EBX */
    1,      /* C: POP ESP */
    1,      /* D: POP EBP */
    1,      /* E: POP ESI */
    1,      /* F: POP EDI */
    
    /* 0x60 - 0x6F */
    1,      /* 0: PUSHA */
    1,      /* 1: POPA */
    1|MODRM,/* 2: BOUND */
    1|MODRM,/* 3: ARPL */
    PREFIX, /* 4: prefix */
    PREFIX, /* 5: prefix */
    PREFIX, /* 6: prefix */
    PREFIX, /* 7: prefix */
    1|OPND_WD,/* 8: PUSH imm16/32 */
    1|MODRM|OPND_WD,/* 9: IMUL */
    1+1,    /* A: PUSH imm8 */
    2|MODRM,/* B: IMUL */
    1,      /* C: INSB */
    1,      /* D: INSW */
    1,      /* E: OUTSB */
    1,      /* F: OUTSW */
    
    /* 0x70 - 0x7F */
    1+1,    /* 0: JO */
    1+1,    /* 1: JNO */
    1+1,    /* 2: JB */
    1+1,    /* 3: JNB */
    1+1,    /* 4: JZ */
    1+1,    /* 5: JNZ */
    1+1,    /* 6: JBE */
    1+1,    /* 7: JA */
    1+1,    /* 8: JS */
    1+1,    /* 9: JNS */
    1+1,    /* A: JP */
    1+1,    /* B: JNP */
    1+1,    /* C: JL */
    1+1,    /* D: JNL */
    1+1,    /* E: JLE */
    1+1,    /* F: JNLE */
    
    /* 0x80 - 0x8F */
    2|MODRM,/* 0: ADD modrm, imm8 */
    2|MODRM,/* 1: ADD modrm, imm8 */
    2|MODRM,/* 2: SUB/CMP modrm, imm8 */
    2|MODRM,/* 3: SUB/CMP modrm, imm8 */
    1|MODRM,/* 4: TEST modrm, modrm */
    1|MODRM,/* 5: TEST modrm, modrm */
    1|MODRM,/* 6: XCHG modrm, modrm */
    1|MODRM,/* 7: XCHG modrm, modrm */
    1|MODRM,/* 8: MOV modrm 8 */
    1|MODRM,/* 9: MOV modrm 16/32 */
    1|MODRM,/* A: MOV modrm 8 reverse */
    1|MODRM,/* B: MOV modrm 16/32 reverse */
    1|MODRM,/* C: MOV modrm 16 seg */
    1|MODRM,/* D: LEA modrm */
    1|MODRM,/* E: MOV modrm 16 seg reverse */
    1|MODRM,/* F: POP... modrm (only this indexed opcode) */
    
    /* 0x90 - 0x9F */
    1,      /* 0: NOP */
    1,      /* 1: XCHG EAX, ECX */
    1,      /* 3: XCHG EAX, EDX */
    1,      /* 3: XCHG EAX, EBX */
    1,      /* 4: XCHG EAX, ESP */
    1,      /* 5: XCHG EAX, EBP */
    1,      /* 6: XCHG EAX, ESI */
    1,      /* 7: XCHG EAX, EDI */
    1,      /* 8: CBW */
    1,      /* 9: CWD */
    1|OPND_PP, /* A: CALL (32 or 48 bit immed ptr) */
    1,      /* B: WAIT */
    1,      /* C: PUSHF */
    1,      /* D: POPF */
    1,      /* E: SAHF */
    1,      /* F: LAHF */
    
    /* 0xA0 - 0xAF */
    1|ADDR_WD,/* 0: MOV AL,rm */
    1|ADDR_WD,/* 1: MOV EAX,rm */
    1|ADDR_WD,/* 2: MOV rm,AL */
    1|ADDR_WD,/* 3: MOV rm,EAX */
    1,      /* 4: MOVSB */
    1,      /* 5: MOVSW */
    1,      /* 6: CMPSB */
    1,      /* 7: CMPSW */
    1+1,    /* 8: TEST AL, imm8 */
    1|OPND_WD,/* 9: TEST EAX, imm16/32 */
    1,      /* A: STOSB */
    1,      /* B: STOSW */
    1,      /* C: LODSB */
    1,      /* D: LODSW */
    1,      /* E: SCASB */
    1,      /* F: SCASW */
    
    /* 0xB0 - 0xBF */
    1+1,    /* 0: MOV AL, imm8 */
    1+1,    /* 1: MOV CL, imm8 */
    1+1,    /* 2: MOV DL, imm8 */
    1+1,    /* 3: MOV BL, imm8 */
    1+1,    /* 4: MOV AH, imm8 */
    1+1,    /* 5: MOV CH, imm8 */
    1+1,    /* 6: MOV DH, imm8 */
    1+1,    /* 7: MOV BH, imm8 */
    1|OPND_WD,/* 8: MOV EAX, imm16/32 */
    1|OPND_WD,/* 9: MOV ECX, imm16/32 */
    1|OPND_WD,/* A: MOV EDX, imm16/32 */
    1|OPND_WD,/* B: MOV EBX, imm16/32 */
    1|OPND_WD,/* C: MOV ESP, imm16/32 */
    1|OPND_WD,/* D: MOV EBP, imm16/32 */
    1|OPND_WD,/* E: MOV ESI, imm16/32 */
    1|OPND_WD,/* F: MOV EDI, imm16/32 */
    
    /* 0xC0 - 0xCF */
    2|MODRM,/* 0: ROL... r/m8, imm8 */
    2|MODRM,/* 1: ROL... r/m16/32, imm8 */
    1+2,    /* 2: RETN */
    1,      /* 3: RETN */
    1|MODRM,/* 4: LES */
    1|MODRM,/* 5: LDS */
    2|MODRM,/* 6: MOV... modrm, imm8 (only this indexed opcode) */
    1|MODRM|OPND_WD,/* 7: MOV... modrm, imm16/32 (only this indexed opcode) */
    1+2+1,  /* 8: ENTER */
    1,      /* 9: LEAVE */
    1+2,    /* A: RETF */
    1,      /* B: RETF */
    1,      /* C: INT3 */
    1+1,    /* D: INT */
    1,      /* E: INTO */
    1,      /* F: IRET */
    
    /* 0xD0 - 0xDF */
    1|MODRM,/* 0: ROL... modrm8, 1 */
    1|MODRM,/* 1: ROL... modrm16/32, 1 */
    1|MODRM,/* 2: ROL... modrm8, CL */
    1|MODRM,/* 3: ROL... modrm16/32, CL */
    1+1,    /* 4: AAM imm8 */
    1+1,    /* 5: AAD imm8 */
    1,      /* 6: SALC */
    1,      /* 7: XLAT */
    1|MODRM,/* 8: ESC/FP */
    1|MODRM,/* 9: ESC/FP */
    1|MODRM,/* A: ESC/FP */
    1|MODRM,/* B: ESC/FP */
    1|MODRM,/* C: ESC/FP */
    1|MODRM,/* D: ESC/FP */
    1|MODRM,/* E: ESC/FP */
    1|MODRM,/* F: ESC/FP */
    
    /* 0xE0 - 0xEF */
    1+1,    /* 0: LOOPNZ */
    1+1,    /* 1: LOOPZ */
    1+1,    /* 2: LOOP */
    1+1,    /* 3: JCXZ */
    1+1,    /* 4: IN AL, imm8 */
    1+1,    /* 5: IN EAX, imm8 */
    1+1,    /* 6: OUT, imm8, AL */
    1+1,    /* 7: OUT, imm8, EAX */
    1|OPND_WD,/* 8: CALL imm16/32 relative ptr */
    1|OPND_WD,/* 9: JMP imm16/32 relative ptr */
    1|OPND_PP,/* A: JMP (32- or 48-bit immed ptr) */
    1+1,    /* B: JMP imm8 relative ptr */
    1,      /* C: IN AL, DX */
    1,      /* D: IN EAX, DX */
    1,      /* E: OUT DX, AL */
    1,      /* F: OUT DX, EAX */
    
    /* 0xF0 - 0xFF */
    PREFIX, /* 0: prefix */
    1,      /* 1: INT1/ICEBP */
    PREFIX, /* 2: prefix */
    PREFIX, /* 3: prefix */
    1,      /* 4: HLT */
    1,      /* 5: CMC */
    MULTI,  /* 6: TEST... 8-bit */
    MULTI,  /* 7: TEST... 16/32-bit */
    1,      /* 8: CLC */
    1,      /* 9: STC */
    1,      /* A: CLI */
    1,      /* B: STI */
    1,      /* C: CLD */
    1,      /* D: STD */
    1|MODRM,/* E: INC/DEC */
    MULTI   /* F: INC/DEC/CALL/JMP/PUSH */
};

static const unsigned char opinfos_twobyte[256] = {
    /* 0x00 - 0x0F */
    1|MODRM,/* 0: SLDT... */
    1|MODRM,/* 1: SGDT... */
    1|MODRM,/* 2: LAR modrm, modrm */
    ILLEGAL,
    ILLEGAL,
    1,      /* 5: SYSCALL */
    1,      /* 6: CLTS */
    1,      /* 7: SYSRET */
    ILLEGAL,
    1,      /* 9: WBINVD */
    ILLEGAL,
    1,      /* B: UD2 */
    ILLEGAL,
    1|MODRM,/* D: PREFETCHW */
    ILLEGAL,
    ILLEGAL,
    
    /* 0x10 - 0x1F */
    1|MODRM,/* 0: MOVLPS/MOVSD/MOVSS/MOVUPS (depends on prefix) */
    1|MODRM,/* 1: MOVLPS/MOVSD/MOVSS/MOVUPS (depends on prefix) */
    1|MODRM,/* 2: MOVDDUP/MOVHLPS/MOVLPD/MOVSLDUP */
    1|MODRM,/* 3: MOVLDP */
    1|MODRM,/* 4: UNPCKLPD/UNPCKLPS */
    1|MODRM,/* 5: UNPCKHPD/UNPCKHPS */
    1|MODRM,/* 6: MOVHPD/MOVLHPS/MOVSHDUP */
    1|MODRM,/* 7: MOVHPD/MOVHPS */
    1|MODRM,/* 8: PREFETCH... */
    1|MODRM,/* 9: HINT NOP (?) */
    1|MODRM,/* A: HINT NOP (?) */
    1|MODRM,/* B: HINT NOP (?) */
    1|MODRM,/* C: HINT NOP (?) */
    1|MODRM,/* D: HINT NOP (?) */
    1|MODRM,/* E: HINT NOP (?) */
    1|MODRM,/* F: HINT NOP modrm */
    
    /* 0x20 - 0x2F */
    1|MODRM,/* 0: MOV modrm, CRn */
    1|MODRM,/* 1: MOV modrm, DRn */
    1|MODRM,/* 2: MOV CRn, modrm */
    1|MODRM,/* 3: MOV DRn, modrm */
    ILLEGAL,
    ILLEGAL,
    ILLEGAL,
    ILLEGAL,
    1|MODRM,/* 8: MOVAPD/MOVAPS */
    1|MODRM,/* 9: MOVAPD/MOVAPS */
    1|MODRM,/* A: CVTPI2PD */
    1|MODRM,/* B: MOVNTPS/MOVNTPD */
    1|MODRM,/* C: CVTTPD2PI */
    1|MODRM,/* D: CVTPD2PI */
    1|MODRM,/* E: UCOMISD/UCOMISS */
    1|MODRM,/* F: COMISD/COMISS */
    
    /* 0x30 - 0x3F */
    1,      /* 0: WRMSR */
    1,      /* 1: RDTSC */
    1,      /* 2: RDMSR */
    ILLEGAL,
    1,      /* 4: SYSENTER */
    1,      /* 5: SYSEXIT */
    ILLEGAL,
    ILLEGAL,
    ILLEGAL, /* 8: PREFIX (not implemented) */
    ILLEGAL,
    ILLEGAL, /* A: PREFIX (not implemented) */
    ILLEGAL,
    ILLEGAL,
    ILLEGAL,
    ILLEGAL,
    ILLEGAL,
    
    /* 0x40 - 0x4F */
    1|OPND_WD,/* 0: CMOVO */
    1|OPND_WD,/* 1: CMOVNO */
    1|OPND_WD,/* 2: CMOVB/CMOVC/CMOVNAE */
    1|OPND_WD,/* 3: CMOVAE/CMOVNB/CMOVNC */
    1|OPND_WD,/* 4: CMOVE/CMOVZ */
    1|OPND_WD,/* 5: CMOVNE/CMOVNZ */
    1|OPND_WD,/* 6: CMOVBE/CMOVNA */
    1|OPND_WD,/* 7: CMOVA/CMOVNBE */
    1|OPND_WD,/* 8: CMOVS */
    1|OPND_WD,/* 9: CMOVNS */
    1|OPND_WD,/* A: CMOVP/CMOVPE */
    1|OPND_WD,/* B: CMOVNP/CMOVPO */
    1|OPND_WD,/* C: CMOVL/CMOVNGE */
    1|OPND_WD,/* D: CMOVGE/CMOVNL */
    1|OPND_WD,/* E: CMOVLE/CMOVNG */
    1|OPND_WD,/* F: CMOVG/CMOVNLE */
    
    /* 0x50 - 0x5F */
    1|MODRM,/* 0: MOVMSKPS/MOVMSKPSD */
    1|MODRM,/* 1: SQRTPD */
    1|MODRM,/* 2: RSQRTPS */
    1|MODRM,/* 3: RCPSS */
    1|MODRM,/* 4: ANDPD */
    1|MODRM,/* 5: ANDNPD */
    1|MODRM,/* 6: ORPD */
    1|MODRM,/* 7: XORPD */
    1|MODRM,/* 8: ADDPD */
    1|MODRM,/* 9: MULPD */
    1|MODRM,/* A: CVTPD2PS/CVTSD2SS */
    1|MODRM,/* B: CVTPS2DQ/CVTTPS2DQ */
    1|MODRM,/* C: SUBPD */
    1|MODRM,/* D: MINPD/MINSD/MINSS */
    1|MODRM,/* E: DIVPD/DIVSD/DIVSS */
    1|MODRM,/* F: MAXPD/MAXSD/MAXSS */
    
    /* 0x60 - 0x6F */
    1|MODRM,/* 0: PUNPCKLBW */
    1|MODRM,/* 1: PUNPCKLWD */
    1|MODRM,/* 2: PUNPCKLDQ */
    1|MODRM,/* 3: PACKSSWB */
    1|MODRM,/* 4: PCMPGTB */
    1|MODRM,/* 5: PCMPGTW */
    1|MODRM,/* 6: PCMPGTD */
    1|MODRM,/* 7: PACKUSWB */
    1|MODRM,/* 8: PUNPCKHBW */
    1|MODRM,/* 9: PUNPCKHWD */
    1|MODRM,/* A: PUNPCKHDQ */
    1|MODRM,/* B: PACKSSDW */
    1|MODRM,/* C: PUNPCKLQDQ */
    1|MODRM,/* D: PUNPCKHQDQ */
    1|MODRM,/* E: MOVD */
    1|MODRM,/* F: MOVDQA/MOVDQU/MOVQ */
    
    /* 0x70 - 0x7F */
    2|MODRM,/* 0: PSHUFD */
    2|MODRM,/* 1: PSLLW */
    2|MODRM,/* 2: PSLLD */
    2|MODRM,/* 3: PSLLQ */
    1|MODRM,/* 4: PCMPEQB */
    1|MODRM,/* 5: PCMPEQW */
    1|MODRM,/* 6: PCMPEQD */
    1,      /* 7: EMMS */
    ILLEGAL,
    ILLEGAL,
    ILLEGAL,
    ILLEGAL,
    1|MODRM,/* C: HADDPD */
    1|MODRM,/* D: HSUBPD */
    1|MODRM,/* E: MOVD */
    1|MODRM,/* F: MOVDQA/MOVDQU/MOVQ */
    
    /* 0x80 - 0x8F */
    1|OPND_WD,/* 0: JO */
    1|OPND_WD,/* 1: JNO */
    1|OPND_WD,/* 2: JB/JC/JNAE */
    1|OPND_WD,/* 3: JAE/JNB/JNC */
    1|OPND_WD,/* 4: JE/JZ */
    1|OPND_WD,/* 5: JNE/JNZ */
    1|OPND_WD,/* 6: JBE/JNA */
    1|OPND_WD,/* 7: JA/JNBE */
    1|OPND_WD,/* 8: JS */
    1|OPND_WD,/* 9: JNS */
    1|OPND_WD,/* A: JP/JPE */
    1|OPND_WD,/* B: JNP/JPO */
    1|OPND_WD,/* C: JL/JNGE */
    1|OPND_WD,/* D: JGE/JNL */
    1|OPND_WD,/* E: JLE/JNG */
    1|OPND_WD,/* F: JG/JNLE */
    
    /* 0x90 - 0x9F */
    1|OPND_WD,/* 0: SETO */
    1|OPND_WD,/* 1: SETNO */
    1|OPND_WD,/* 2: SETB/SETC/SETNAE */
    1|OPND_WD,/* 3: SETAE/SETNB/SETNC */
    1|OPND_WD,/* 4: SETE/SETZ */
    1|OPND_WD,/* 5: SETNE/SETNZ */
    1|OPND_WD,/* 6: SETBE/SETNA */
    1|OPND_WD,/* 7: SETA/SETNBE */
    1|OPND_WD,/* 8: SETS */
    1|OPND_WD,/* 9: SETNS */
    1|OPND_WD,/* A: SETP/SETPE */
    1|OPND_WD,/* B: SETNP/SETPO */
    1|OPND_WD,/* C: SETL/SETNGE */
    1|OPND_WD,/* D: SETGE/SETNL */
    1|OPND_WD,/* E: SETLE/SETNG */
    1|OPND_WD,/* F: SETG/SETNLE */
    
    /* 0xA0 - 0xAF */
    1,      /* 0: PUSH FS */
    1,      /* 1: POP FS */
    1,      /* 2: CPUID */
    1|MODRM,/* 3: BT modrm */
    2|MODRM,/* 4: SHLD modrm, imm8 */
    1|MODRM,/* 5: SHLD modrm, CL */
    ILLEGAL,
    ILLEGAL,
    1,      /* 8: PUSH GS */
    1,      /* 9: POP GS */
    1,      /* A: RSM */
    1|MODRM,/* B: BTS modrm */
    2|MODRM,/* C: SHRD modrm, imm8 */
    1|MODRM,/* D: SHRD modrm, CL */
    /*2,*/  /* E: SFENCE/LFENCE/MFENCE(?) */
    1|MODRM,/* E: FXSAVE... */
    1|MODRM,/* F: IMUL modrm, modrm */
    
    /* 0xB0 - 0xBF */
    1|MODRM,/* 0: CMPXCHG modrm, modrm */
    1|MODRM,/* 1: CMPXCHG modrm, modrm */
    1|MODRM,/* 2: LSS modrm, modrm */
    1|MODRM,/* 3: BTR modrm */
    1|MODRM,/* 4: LFS modrm, modrm */
    1|MODRM,/* 5: LGS modrm, modrm */
    1|MODRM,/* 6: MOVZX modrm, modrm */
    1|MODRM,/* 7: MOVZX modrm, modrm */
    1|MODRM,/* 8: POPCNT modrm, modrm */
    1,      /* 9: UD (?) */
    1|MODRM,/* A: BTx... modrm, imm8 */
    1|MODRM,/* B: BTC modrm */
    1|MODRM,/* C: BSF modrm, modrm */
    1|MODRM,/* D: BSR modrm, modrm */
    1|MODRM,/* E: MOVSX modrm, modrm */
    1|MODRM,/* F: MOVSX modrm, modrm */
    
    /* 0xC0 - 0xCF */
    1|MODRM,/* 0: XADD modrm, modrm */
    1|MODRM,/* 1: XADD modrm, modrm */
    2|MODRM,/* 5: CMPPD */
    1|MODRM,/* 3: MOVNTI */
    2|MODRM,/* 4: PINSRW */
    2|MODRM,/* 5: PEXTRW */
    2|MODRM,/* 6: SHUFPS */
    1|MODRM,/* 7: CMPXCHGxB... modrm */
    1,      /* 8: BSWAP EAX */
    1,      /* 9: BSWAP ECX */
    1,      /* A: BSWAP EDX */
    1,      /* B: BSWAP EBX */
    1,      /* C: BSWAP ESP */
    1,      /* D: BSWAP EBP */
    1,      /* E: BSWAP ESI */
    1,      /* F: BSWAP EDI */
    
    
    /* 0xD0 - 0xDF */
    1|MODRM,/* 0: ADDSUBPD */
    1|MODRM,/* 1: PSRLW */
    1|MODRM,/* 2: PSRLD */
    1|MODRM,/* 3: PSRLQ */
    1|MODRM,/* 4: PADDQ */
    1|MODRM,/* 5: PMULLW */
    1|MODRM,/* 6: MOVDQ2Q/MOVQ/MOVQ2DQ */
    1|MODRM,/* 7: PMOVMSKB */
    1|MODRM,/* 8: PSUBUSB modrm */
    1|MODRM,/* 9: PSUBUSW modrm */
    1|MODRM,/* A: PMINUB */
    1|MODRM,/* B: PAND */
    1|MODRM,/* C: PADDUSB */
    1|MODRM,/* D: PADDUSW */
    1|MODRM,/* E: PMAXUB */
    1|MODRM,/* F: PANDN */
    
    /* 0xE0 - 0xEF */
    1|MODRM,/* 0: PAVGB */
    1|MODRM,/* 1: PSRAW */
    1|MODRM,/* 2: PSRAD */
    1|MODRM,/* 3: PAVGW */
    1|MODRM,/* 4: PMULHUW */
    1|MODRM,/* 5: PMULHW */
    1|MODRM,/* 6: CVTDQ2PD */
    1|MODRM,/* 7: MOVNTQ/MOVNTDQ */
    1|MODRM,/* 8: PSUBSB modrm */
    1|MODRM,/* 9: PSUBSW modrm */
    1|MODRM,/* A: PMINSW */
    1|MODRM,/* B: POR */
    1|MODRM,/* C: PADDSB */
    1|MODRM,/* D: PADDSW */
    1|MODRM,/* E: PMAXSW */
    1|MODRM,/* F: PXOR */
    
    /* 0xF0 - 0xFF */
    1|MODRM,/* 0: MOVBE (with prefix after 0x0F/TWOBYTE), LDDQU */
    1|MODRM,/* 1: PSLLW */
    1|MODRM,/* 2: PSLLD */
    1|MODRM,/* 3: PSLLQ */
    1|MODRM,/* 4: PMULUDQ */
    1|MODRM,/* 5: PMADDWD */
    1|MODRM,/* 6: PSADBW */
    1|MODRM,/* 7: MASKMOVQ */
    1|MODRM,/* 8: PSUBB */
    1|MODRM,/* 9: PSUBW */
    1|MODRM,/* A: PSUBD */
    1|MODRM,/* B: PSUBQ */
    1|MODRM,/* C: PADDB */
    1|MODRM,/* D: PADDW */
    1|MODRM,/* E: PADDD */
    ILLEGAL
};

static unsigned char get_modrm_extra(int is16, int mod, int rm)
{
    if (is16) {
        switch (mod) {
            case 0: return (rm == 0x6 ? 2 : 0);
            case 1: return 1;
            case 2: return 2;
            case 3: return 0;
        }
    } else {
        int sib = (rm == 0x4 ? 1 : 0);
        switch (mod) {
            case 0: return (rm == 0x5 ? 4 : sib);
            case 1: return sib+1;
            case 2: return sib+4;
            case 3: return 0;
        }
    }
}

/* Instructions with only one format are not handled here:
   80, 81, 83, 8F, C1, C6, C7, D1, D2, D3, D8...DF, FE,
   0F_00, 0F_01, 0F_18, 0F_1F_ 0F_AE, 0F_BA, 0F_C7 */
static unsigned char get_idx_opinfo(unsigned char opc, unsigned char idx)
{
    switch (opc<<4 | idx) {
    case 0xF60: /* TEST */
        return 2|MODRM;
    /* is there an F6 /1 ? */
    case 0xF62: /* NOT */
    case 0xF63: /* NEG */
    case 0xF64: /* IMUL */
    case 0xF65: /* IMUL */
    case 0xF66: /* DIV */
    case 0xF67: /* IDIV */
        return 1|MODRM;
    
    case 0xF70: /* TEST */
        return 1|MODRM|OPND_WD;
    /* is there an F7 /1 ? */
    case 0xF72: /* NOT */
    case 0xF73: /* NEG */
    case 0xF74: /* IMUL */
    case 0xF75: /* IMUL */
    case 0xF76: /* DIV */
    case 0xF77: /* IDIV */
        return 1|MODRM;
    
    case 0xFF0: /* INC */
    case 0xFF1: /* DEC */
    case 0xFF2: /* CALL */
    case 0xFF3: /* CALL */
    case 0xFF4: /* JMP */
        return 1|MODRM;
    case 0xFF5: /* JMP */
        return 1|MODRM|OPND_WD;
    case 0xFF6: /* PUSH */
        return 1|MODRM;
    default:
        return ILLEGAL;
    }
}

unsigned char get_x86_instr_size(const unsigned char *code, unsigned long start, unsigned long codelen)
{
    const char *p, *end;
    BYTE c;
    BYTE opinfo;
    int opnd16 = 0, addr16 = 0;
    BYTE instrlen = 0;
    
    if (start >= codelen) return 0;
    p = &code[start];
    end = &code[codelen];
    
    /* Prefixes */
    for (;;) {
        c = *p;
        opinfo = opinfos[c];
        if (opinfo != PREFIX) break;
        if (c == 0x66) {
            if (!opnd16) opnd16 = 1;
            else return ILLEGAL_INSTR_SIZE;
        }
        if (c == 0x67) {
            if (!addr16) addr16 = 1;
            else return ILLEGAL_INSTR_SIZE;
        }
        instrlen++;
        if (++p >= end) return ILLEGAL_INSTR_SIZE;
    }
    
    /* Opcode */
    if (opinfo == TWOBYTE) {
        if (++p >= end) return ILLEGAL_INSTR_SIZE;
        c = *p;
        opinfo = opinfos_twobyte[c];
        if (opinfo == ILLEGAL) return ILLEGAL_INSTR_SIZE;
        instrlen++;
    }
    
    if (opinfo == MULTI) {
        /* Instruction index in Mod-R/M */
        BYTE opc = c, idx;
        if (++p >= end) return ILLEGAL_INSTR_SIZE;
        c = *p;
        instrlen += 1 + get_modrm_extra(opnd16, (int)c>>6, c&0x7);
        idx = (c&0x38)>>3;
        opinfo = get_idx_opinfo(opc, idx);
    } else if ((opinfo & MODRM) != 0) {
        /* Normal Mod-R/M */
        if (++p >= end) return ILLEGAL_INSTR_SIZE;
        c = *p;
        instrlen += 1 + get_modrm_extra(opnd16, (int)c>>6, c&0x7);
    }
    
    /* Variable size (16/32/48) arguments */
    switch (opinfo & OPNDADDRMASK) {
        case OPND_WD: instrlen += (opnd16 ? 2 : 4); break;
        case OPND_PP: instrlen += (opnd16 ? 2 : 4); break;
        case ADDR_WD: instrlen += (addr16 ? 2 : 4); break;
        default: ;
    }
    
    /* Add size of opcode + size of immediate operands */
    instrlen += opinfo & 0xF;
    return instrlen;
}


