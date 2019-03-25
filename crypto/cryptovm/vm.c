
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <gmp.h>

#ifndef DEBUG
#define DEBUG 0
#endif

struct rsaKey {
    unsigned int bytes;
    unsigned char n[256];
    unsigned char exp[256];
} __attribute__((packed));

#define CODESIZE (1024*1024)
#define FLAG_SIZE 1024

#define MODEWEAK 0
#define MODESTRONG 1

#define WEAKBYTES 128
#define STRONGBYTES 256

#define NUM_KEYS 16
#define NUM_MEM 16

#define MEM_SIZE 512

struct vm_state {
    struct rsaKey rsaKeys[NUM_KEYS];
    char flag[FLAG_SIZE];
    unsigned char isSuperUser;
    unsigned char isDebug;
    int codeSize;
    unsigned char code[CODESIZE];
    unsigned int ip;
    unsigned char mem[NUM_MEM][MEM_SIZE];
    struct rsaKey currentKey;
};

#define OP_FLAG 0
#define OP_GETPUB 1
#define OP_SETMODE 2
#define OP_LOADPRIV 3
#define OP_LOADPUB 4
#define OP_RSA 5
#define OP_SUDO 6
#define OP_SETMEM 7
#define OP_ADD 8
#define OP_SUB 9
#define OP_MUL 10
#define OP_DIV 11
#define OP_MOD 12
#define OP_POWMOD 13
#define OP_INVERT 14
#define OP_PRINT 15
#define OP_EXIT 100


#define SUPERUSER_MSG "Please give me superuser permissions"

void loadnum(mpz_t n, unsigned char *mem, int bytes) {
    mpz_init(n);
    mpz_set_ui(n, 0);
    int i;
    for (i = bytes - 1; i >= 0; i--) {
        mpz_mul_ui(n, n, 256);
        mpz_add_ui(n, n, mem[i]);
    }
}

void savenum(mpz_t n, unsigned char *mem, int bytes) {
   int i;
   mpz_t r;
   mpz_init(r);
   for (i=0; i < bytes; i++) {
      mpz_mdivmod_ui(n, r, n, 256);
      mem[i] = mpz_get_ui(r);
   }
   mpz_clear(r);
   mpz_clear(n);
}

void add(unsigned char *a, unsigned char *b, unsigned char *c) {
   mpz_t ma, mb, mc;
   loadnum(ma, a, MEM_SIZE);
   loadnum(mb, b, MEM_SIZE);
   mpz_init(mc);
   mpz_add(mc, ma, mb);
   savenum(mc, c, MEM_SIZE);
   mpz_clear(ma);
   mpz_clear(mb);
}

void sub(unsigned char *a, unsigned char *b, unsigned char *c) {
   mpz_t ma, mb, mc;
   loadnum(ma, a, MEM_SIZE);
   loadnum(mb, b, MEM_SIZE);
   mpz_init(mc);
   mpz_sub(mc, ma, mb);
   savenum(mc, c, MEM_SIZE);
   mpz_clear(ma);
   mpz_clear(mb);
}

void mul(unsigned char *a, unsigned char *b, unsigned char *c) {
   mpz_t ma, mb, mc;
   loadnum(ma, a, MEM_SIZE);
   loadnum(mb, b, MEM_SIZE);
   mpz_init(mc);
   mpz_mul(mc, ma, mb);
   savenum(mc, c, MEM_SIZE);
   mpz_clear(ma);
   mpz_clear(mb);
}

void divx(unsigned char *a, unsigned char *b, unsigned char *c) {
   mpz_t ma, mb, mc;
   loadnum(mb, b, MEM_SIZE);
   if (mpz_cmp_ui(mb, 0) == 0) {
      mpz_clear(mb);
      return;
   }
   loadnum(ma, a, MEM_SIZE);
   mpz_init(mc);
   mpz_div(mc, ma, mb);
   savenum(mc, c, MEM_SIZE);
   mpz_clear(ma);
   mpz_clear(mb);
}

void mod(unsigned char *a, unsigned char *b, unsigned char *c) {
   mpz_t ma, mb, mc;
   loadnum(mb, b, MEM_SIZE);
   if (mpz_cmp_ui(mb, 0) <= 0) {
      mpz_clear(mb);
      return;
   }
   loadnum(ma, a, MEM_SIZE);
   mpz_init(mc);
   mpz_mod(mc, ma, mb);
   savenum(mc, c, MEM_SIZE);
   mpz_clear(ma);
   mpz_clear(mb);
}

void powmod(unsigned char *a, unsigned char *b, unsigned char *c, unsigned char *d) {
   mpz_t ma, mb, mc, md;
   loadnum(mc, c, MEM_SIZE);
   if (mpz_cmp_ui(mc, 0) <= 0) {
      mpz_clear(mc);
      return;
   }
   loadnum(ma, a, MEM_SIZE);
   loadnum(mb, b, MEM_SIZE);
   mpz_init(md);
   mpz_powm(md, ma, mb, mc);
   savenum(md, d, MEM_SIZE);
   mpz_clear(ma);
   mpz_clear(mb);
   mpz_clear(mc);
}

void invert(unsigned char *a, unsigned char *b, unsigned char *c) {
   mpz_t ma, mb, mg, ms, mt;
   loadnum(mb, b, MEM_SIZE);
   if (mpz_cmp_ui(mb, 0) <= 0) {
      mpz_clear(mb);
      return;
   }
   loadnum(ma, a, MEM_SIZE);
   mpz_init(mg);
   mpz_init(ms);
   mpz_init(mt);
   mpz_gcdext(mg, ms, mt, ma, mb);
   mpz_mod(ms, ms, mb);
   savenum(ms, c, MEM_SIZE);
   mpz_clear(ma);
   mpz_clear(mb);
   mpz_clear(mg);
   mpz_clear(mt);
}

int do_flag(struct vm_state *x) {
    if (x->isSuperUser == 1) {
       puts(x->flag);
       return 0;
    }
    return -1;
}

int do_getpub(struct vm_state *x) {
    if (x->ip + 1 >= x->codeSize) {
        return -1;
    }
    unsigned char key_slot = x->code[x->ip++];
    unsigned char mem_slot = x->code[x->ip++];
    if (key_slot >= NUM_KEYS) return -1;
    if (mem_slot >= NUM_MEM) return -1;
    memset(x->mem[mem_slot], 0, MEM_SIZE);
    memcpy(x->mem[mem_slot], x->rsaKeys[key_slot].n, x->rsaKeys[key_slot].bytes);
    return 0;
}

int do_setmode(struct vm_state *x) {
    if (x->ip >= x->codeSize) {
        return -1;
    }

    unsigned char mode = x->code[x->ip++];

    switch(mode) {
        case MODEWEAK: x->currentKey.bytes = WEAKBYTES; break;
        case MODESTRONG: x->currentKey.bytes = STRONGBYTES; break;
        default: return -1;
    }
    return 0;
}

int do_loadpriv(struct vm_state *x) {
    if (x->ip >= x->codeSize) {
        return -1;
    }

    if (x->currentKey.bytes != WEAKBYTES && x->isSuperUser == 0) return -1;
    unsigned char key_slot = x->code[x->ip++];
    if (key_slot >= NUM_KEYS) return -1;
    memcpy(x->currentKey.exp, x->rsaKeys[key_slot].exp, x->currentKey.bytes);
    memcpy(x->currentKey.n, x->rsaKeys[key_slot].n, x->currentKey.bytes);
    return 0;
}

int do_loadpub(struct vm_state *x) {
    if (x->ip >= x->codeSize) {
        return -1;
    }
    unsigned char key_slot = x->code[x->ip++];
    if (key_slot >= NUM_KEYS) return -1;
    memset(x->currentKey.exp, 0, x->currentKey.bytes);
    memcpy(x->currentKey.exp, "\x01\x00\x01", 3);
    memcpy(x->currentKey.n, x->rsaKeys[key_slot].n, x->currentKey.bytes);
    return 0;
}

void rsa(struct rsaKey* key, unsigned char *msg, unsigned char* signature) {
    mpz_t m,d,s, n;
    loadnum(m, msg, key->bytes);
    loadnum(n, key->n, key->bytes);
    loadnum(d, key->exp, key->bytes);
    mpz_init(s);
    mpz_powm(s, m, d, n);
    savenum(s, signature, MEM_SIZE);
    mpz_clear(m);
    mpz_clear(d);
    mpz_clear(n);
}

int do_rsa(struct vm_state *x) {
   if (x->ip + x->currentKey.bytes >= x->codeSize) return -1;
   unsigned char msg[x->currentKey.bytes];
   memcpy(msg, &x->code[x->ip], x->currentKey.bytes);
   x->ip += x->currentKey.bytes;
   unsigned char mem_slot = x->code[x->ip++];
   if (mem_slot >= NUM_MEM) return -1;
   rsa(&x->currentKey, msg, x->mem[mem_slot]);
   return 0;
}

int verify(struct rsaKey* key, unsigned char *signature, unsigned char *msg) {
    mpz_t m,e,s,mm,n;
    loadnum(m, msg, MEM_SIZE);
    loadnum(s, signature, MEM_SIZE);
    loadnum(n, key->n, key->bytes);
    mpz_init(e);
    mpz_set_ui(e, 65537);
    mpz_init(mm);
    mpz_powm(mm, s, e, n);
    
    int res = mpz_cmp(mm, m);

    mpz_clear(m);
    mpz_clear(e);
    mpz_clear(s);
    mpz_clear(mm);
    mpz_clear(n);
    return res;
}

int do_sudo(struct vm_state *x) {
    if (x->ip + 1 >= x->codeSize) {
        return -1;
    }
    unsigned char key_slot = x->code[x->ip++];
    unsigned char mem_slot = x->code[x->ip++];
    if (key_slot >= NUM_KEYS) return -1;
    if (mem_slot >= NUM_MEM) return -1;
    if (x->rsaKeys[key_slot].bytes != STRONGBYTES) return -1;
    unsigned char msg[MEM_SIZE];
    memset(msg, 0, MEM_SIZE);
    memcpy(msg, SUPERUSER_MSG, strlen(SUPERUSER_MSG));
    if (verify(&x->rsaKeys[key_slot], x->mem[mem_slot], msg) == 0) x->isSuperUser = 1;
    return 0;
}

int do_setmem(struct vm_state *x) {
    if (x->ip + MEM_SIZE >= x->codeSize) {
        return -1;
    }

    unsigned char mem_slot = x->code[x->ip++];
    if (mem_slot >= NUM_MEM) return -1;
    memcpy(x->mem[mem_slot], &x->code[x->ip], MEM_SIZE);
    x->ip += MEM_SIZE;
    return 0;
}


int do_add(struct vm_state *x) {
    if (x->ip + 2  >= x->codeSize) {
        return -1;
    }

    unsigned char a = x->code[x->ip++];
    if (a >= NUM_MEM) return -1;
    unsigned char b = x->code[x->ip++];
    if (b >= NUM_MEM) return -1;
    unsigned char c = x->code[x->ip++];
    if (c >= NUM_MEM) return -1;
    add(x->mem[a], x->mem[b], x->mem[c]);
    return 0;
}

int do_sub(struct vm_state *x) {
    if (x->ip + 2  >= x->codeSize) {
        return -1;
    }

    unsigned char a = x->code[x->ip++];
    if (a >= NUM_MEM) return -1;
    unsigned char b = x->code[x->ip++];
    if (b >= NUM_MEM) return -1;
    unsigned char c = x->code[x->ip++];
    if (c >= NUM_MEM) return -1;
    sub(x->mem[a], x->mem[b], x->mem[c]);
    return 0;
}

int do_mul(struct vm_state *x) {
    if (x->ip + 2  >= x->codeSize) {
        return -1;
    }

    unsigned char a = x->code[x->ip++];
    if (a >= NUM_MEM) return -1;
    unsigned char b = x->code[x->ip++];
    if (b >= NUM_MEM) return -1;
    unsigned char c = x->code[x->ip++];
    if (c >= NUM_MEM) return -1;
    mul(x->mem[a], x->mem[b], x->mem[c]);
    return 0;
}

int do_div(struct vm_state *x) {
    if (x->ip + 2  >= x->codeSize) {
        return -1;
    }

    unsigned char a = x->code[x->ip++];
    if (a >= NUM_MEM) return -1;
    unsigned char b = x->code[x->ip++];
    if (b >= NUM_MEM) return -1;
    unsigned char c = x->code[x->ip++];
    if (c >= NUM_MEM) return -1;
    divx(x->mem[a], x->mem[b], x->mem[c]);
    return 0;
}

int do_mod(struct vm_state *x) {
    if (x->ip + 2  >= x->codeSize) {
        return -1;
    }

    unsigned char a = x->code[x->ip++];
    if (a >= NUM_MEM) return -1;
    unsigned char b = x->code[x->ip++];
    if (b >= NUM_MEM) return -1;
    unsigned char c = x->code[x->ip++];
    if (c >= NUM_MEM) return -1;
    mod(x->mem[a], x->mem[b], x->mem[c]);
    return 0;
}

int do_powmod(struct vm_state *x) {
    if (x->ip + 3  >= x->codeSize) {
        return -1;
    }

    unsigned char a = x->code[x->ip++];
    if (a >= NUM_MEM) return -1;
    unsigned char b = x->code[x->ip++];
    if (b >= NUM_MEM) return -1;
    unsigned char c = x->code[x->ip++];
    if (c >= NUM_MEM) return -1;
    unsigned char d = x->code[x->ip++];
    if (d >= NUM_MEM) return -1;    
    powmod(x->mem[a], x->mem[b], x->mem[c], x->mem[d]);
    return 0;
}

int do_invert(struct vm_state *x) {
    if (x->ip + 2  >= x->codeSize) {
        return -1;
    }

    unsigned char a = x->code[x->ip++];
    if (a >= NUM_MEM) return -1;
    unsigned char b = x->code[x->ip++];
    if (b >= NUM_MEM) return -1;
    unsigned char c = x->code[x->ip++];
    if (c >= NUM_MEM) return -1;
    invert(x->mem[a], x->mem[b], x->mem[c]);
    return 0;
}

void print_slot(struct vm_state *x, unsigned char mem_slot) {
    char buf[MEM_SIZE*3];
    int i;
    for (i=0;i<MEM_SIZE;i++) {
        sprintf(buf+2*i, "%02X", x->mem[mem_slot][i]);
    }
    puts(buf);
}

int do_print(struct vm_state *x) {
    if (x->ip  >= x->codeSize) {
        return -1;
    }

    if (x->isDebug == 0) return -1;
    unsigned char mem_slot = x->code[x->ip++];
    if (mem_slot >= NUM_MEM) return -1;

    print_slot(x, mem_slot);

    return 0;
}

int vm_step(struct vm_state *x) {
    if (x->ip >= x->codeSize) {
        return -1;
    }
    int res = 0;
    unsigned char op = x->code[x->ip++];

    switch (op) {
        case OP_FLAG: res = do_flag(x); break;
        case OP_GETPUB: res = do_getpub(x); break;
        case OP_SETMODE: res = do_setmode(x); break;
        case OP_LOADPRIV: res = do_loadpriv(x); break;
        case OP_LOADPUB: res = do_loadpub(x); break;
        case OP_RSA: res = do_rsa(x); break;
        case OP_SUDO: res = do_sudo(x); break;
        case OP_SETMEM: res = do_setmem(x); break;
        case OP_ADD: res = do_add(x); break;
        case OP_SUB: res = do_sub(x); break;
        case OP_MUL: res = do_mul(x); break;
        case OP_DIV: res = do_div(x); break;
        case OP_MOD: res = do_mod(x); break;
        case OP_POWMOD: res = do_powmod(x); break;
        case OP_INVERT: res = do_invert(x); break;
        case OP_PRINT: res = do_print(x); break;
        case OP_EXIT: puts("done."); res = 1; break;
        default: res = -1;
    }

    if (res < 0) {
      puts("error.");
    }

    return res;
}

int initVM(struct vm_state *x) {
    int len;
    memset(x, 0, sizeof(struct vm_state));
    while(x->codeSize < CODESIZE) {
      len = read(0, x->code + x->codeSize, CODESIZE - x->codeSize);
      if (len <= 0) break;
      x->codeSize += len;
    }
    int fd = open("flag", 0);
    if (fd < 0) return -1;
    int fs = read(fd, x->flag, FLAG_SIZE - 1);
    close(fd);
    x->flag[fs]=0;
    FILE *keyFile = fopen("keys", "rb");
    if (!keyFile) return -1;
    if (fread(x->rsaKeys, sizeof(struct rsaKey), NUM_KEYS, keyFile) != NUM_KEYS) return -1;
    fclose(keyFile);
    x->isDebug = DEBUG;
    return 0;
}

struct vm_state state;

int main(void) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    puts("starting init.");
    if (initVM(&state) != 0) {
      puts("Something is wrong, please contact admin.");
      return -1;
    }
    printf("starting vm. code length = %u\n", state.codeSize);
    while (vm_step(&state) == 0);
    return 0;
}
