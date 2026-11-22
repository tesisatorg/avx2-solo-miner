#!/usr/bin/env python3
# Cok motorlu sha256d tarayici uretecisi: AVX2 (8 serit), AVX-512 zmm (16 serit), AVX-512VL ymm (8 serit, ternlog + ror)
# Kullanim: python3 gen_kernels.py skeleton.c > sha256d_scan.c
import sys
M32=0xffffffff
K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]
IV=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]
ror=lambda x,n:((x>>n)|(x<<(32-n)))&M32
s0i=lambda x:ror(x,7)^ror(x,18)^(x>>3)
s1i=lambda x:ror(x,17)^ror(x,19)^(x>>10)
B0i=lambda x:ror(x,2)^ror(x,13)^ror(x,22)
B1i=lambda x:ror(x,6)^ror(x,11)^ror(x,25)
chi=lambda e,f,g:(g^(e&(f^g)))&M32
maji=lambda a,b,c:((a&b)|(c&(a|b)))&M32

def build(maj_mode):
    st=dict(sl=[],vlA=[],vlB=[],nc=19,vn=0); st['cur']=st['vlA']
    sl=st['sl']
    def newc(expr):
        i=st['nc'];st['nc']+=1;sl.append(f"    c[{i}] = {expr};");return ('c',i)
    def sx(x): return f"0x{x[1]:08x}u" if x[0]=='i' else f"c[{x[1]}]"
    def vx(x):
        if x[0]=='v': return x[1]
        if x[0]=='k': return f"KW[{x[1]}]"
        return f"SET1((int){sx(x)})"
    def emit_v(expr):
        n=f"v{st['vn']}";st['vn']+=1;st['cur'].append(f"    V {n} = {expr};");return ('v',n)
    def sadd(*xs):
        imm=sum(x[1] for x in xs if x[0]=='i')&M32
        cs=[x for x in xs if x[0]=='c']
        if not cs: return ('i',imm)
        if len(cs)==1 and imm==0: return cs[0]
        return newc(" + ".join([sx(x) for x in cs]+([f"0x{imm:08x}u"] if imm else [])))
    def sig(x,which):
        if x[0]=='i': return ('i',(s0i if which==0 else s1i)(x[1]))
        if x[0]=='c':
            s=sx(x)
            return newc(f"ROR32({s},7)^ROR32({s},18)^({s}>>3)" if which==0 else f"ROR32({s},17)^ROR32({s},19)^({s}>>10)")
        return emit_v(f"SIG{which}V({x[1]})")
    def addterms(terms):
        vecs=[t for t in terms if t[0]=='v'];scal=[t for t in terms if t[0]!='v']
        s=sadd(*scal) if scal else ('i',0)
        if not vecs: return s
        e=vecs[0][1]
        for v in vecs[1:]: e=f"ADD({e},{v[1]})"
        if not(s[0]=='i' and s[1]==0): e=f"ADD({e},{vx(s)})"
        return emit_v(e)
    def wnext(w,i): w.append(addterms([w[i-16],sig(w[i-15],0),w[i-7],sig(w[i-2],1)]))
    def kwof2(i,w):
        if w[0]!='v': return sadd(('i',K[i]),w)
        return emit_v(f"ADD({w[1]},SET1((int)0x{K[i]:08x}u))")
    def rnd(m,i,kw,bc,pre,skip_a=False):
        a,b,c,d,e,f,g,h=m; cur=st['cur']
        cur.append(f"    V t_{pre}{i} = ADD(ADD(ADD({h},BS1V({e})),CH({e},{f},{g})),{vx(kw)});")
        cur.append(f"    {d} = ADD({d},t_{pre}{i});")
        if skip_a: return [h,a,b,c,d,e,f,g],None
        if maj_mode:
            cur.append(f"    {h} = ADD(ADD(t_{pre}{i},BS0V({a})),MAJ({a},{b},{c}));")
            return [h,a,b,c,d,e,f,g],None
        cur.append(f"    V ab_{pre}{i} = XOR({a},{b});")
        cur.append(f"    {h} = ADD(ADD(t_{pre}{i},BS0V({a})),XOR({b},AND(ab_{pre}{i},{bc})));")
        return [h,a,b,c,d,e,f,g],f"ab_{pre}{i}"
    # PART A
    st['cur']=st['vlA']; cur=st['cur']
    cur.append("    V nonce_w3 = nonce;")
    w=[('c',8),('c',9),('c',10),('v','nonce_w3'),('i',0x80000000)]+[('i',0)]*10+[('i',640)]
    kwref={}
    cur.append(f"    KW[3] = ADD(nonce_w3,SET1((int)0x{K[3]:08x}u));");kwref[3]=('k',3)
    for i in range(4,16): kwref[i]=sadd(('i',K[i]),w[i])
    for i in range(16,64):
        wnext(w,i)
        if w[i][0]=='v':
            cur.append(f"    KW[{i}] = ADD({w[i][1]},SET1((int)0x{K[i]:08x}u));");kwref[i]=('k',i)
        else: kwref[i]=sadd(('i',K[i]),w[i])
    # PART B
    st['cur']=st['vlB']; cur=st['cur']
    for k,n in enumerate("abcdefgh"): cur.append(f"    V {n}1 = SET1((int)vs->st3[{k}]);")
    if not maj_mode: cur.append("    V bc1 = XOR(b1,c1);")
    m=[f"{n}1" for n in "abcdefgh"];bc="bc1"
    for i in range(3,64): m,bc=rnd(m,i,kwref[i],bc,"p")
    dig=[emit_v(f"ADD({m[k]},SET1((int)vs->mid[{k}]))") for k in range(8)]
    w2=dig+[('i',0x80000000)]+[('i',0)]*6+[('i',256)]
    T1c=(IV[7]+B1i(IV[4])+chi(IV[4],IV[5],IV[6])+K[0])&M32
    T2c=(B0i(IV[0])+maji(IV[0],IV[1],IV[2]))&M32
    cur.append(f"    V t_q0 = ADD({w2[0][1]},SET1((int)0x{T1c:08x}u));")
    cur.append(f"    V a2 = ADD(t_q0,SET1((int)0x{T2c:08x}u));")
    cur.append(f"    V e2 = ADD(t_q0,SET1((int)0x{IV[3]:08x}u));")
    for n,k in zip("bcdfgh",[0,1,2,4,5,6]): cur.append(f"    V {n}2 = SET1((int)0x{IV[k]:08x}u);")
    if not maj_mode: cur.append(f"    V bc2 = SET1((int)0x{IV[0]^IV[1]:08x}u);")
    m=["a2","b2","c2","d2","e2","f2","g2","h2"];bc="bc2"
    for i in range(1,61):
        if i>=16: wnext(w2,i)
        kw=kwof2(i,w2[i]);m,bc=rnd(m,i,kw,bc,"q",skip_a=(i>=57))
    cur.append(f"    return ADD({m[4]},SET1((int)0x{IV[7]:08x}u));")
    return dict(prep="\n".join(sl),sched="\n".join(st['vlA']),hash="\n".join(st['vlB']),nc=st['nc'])

AVX2_MACROS="""#define V __m256i
#define ADD(a,b) _mm256_add_epi32(a,b)
#define XOR(a,b) _mm256_xor_si256(a,b)
#define AND(a,b) _mm256_and_si256(a,b)
#define OR(a,b) _mm256_or_si256(a,b)
#define SHR(x,n) _mm256_srli_epi32(x,n)
#define SHL(x,n) _mm256_slli_epi32(x,n)
#define ROR(x,n) OR(SHR(x,n),SHL(x,32-(n)))
#define SIG0V(x) XOR(XOR(ROR(x,7),ROR(x,18)),SHR(x,3))
#define SIG1V(x) XOR(XOR(ROR(x,17),ROR(x,19)),SHR(x,10))
#define BS0V(x) XOR(XOR(ROR(x,2),ROR(x,13)),ROR(x,22))
#define BS1V(x) XOR(XOR(ROR(x,6),ROR(x,11)),ROR(x,25))
#define CH(e,f,g) XOR(g,AND(e,XOR(f,g)))
#define SET1(x) _mm256_set1_epi32(x)
#define BSWAP(x) _mm256_shuffle_epi8(x,_mm256_setr_epi8(3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12,3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12))
#define LANEIDX _mm256_setr_epi32(0,1,2,3,4,5,6,7)
#define LOADU(p) _mm256_loadu_si256((const __m256i*)(p))
#define STOREU(p,x) _mm256_storeu_si256((__m256i*)(p),x)
#define CMPZ(x) ((unsigned)_mm256_movemask_ps(_mm256_castsi256_ps(_mm256_cmpeq_epi32(x,_mm256_setzero_si256()))))
"""
VL_MACROS="""#define V __m256i
#define ADD(a,b) _mm256_add_epi32(a,b)
#define XOR(a,b) _mm256_xor_si256(a,b)
#define SHR(x,n) _mm256_srli_epi32(x,n)
#define ROR(x,n) _mm256_ror_epi32(x,n)
#define T3(a,b,c,i) _mm256_ternarylogic_epi32(a,b,c,i)
#define SIG0V(x) T3(ROR(x,7),ROR(x,18),SHR(x,3),0x96)
#define SIG1V(x) T3(ROR(x,17),ROR(x,19),SHR(x,10),0x96)
#define BS0V(x) T3(ROR(x,2),ROR(x,13),ROR(x,22),0x96)
#define BS1V(x) T3(ROR(x,6),ROR(x,11),ROR(x,25),0x96)
#define CH(e,f,g) T3(e,f,g,0xCA)
#define MAJ(a,b,c) T3(a,b,c,0xE8)
#define SET1(x) _mm256_set1_epi32(x)
#define BSWAP(x) _mm256_shuffle_epi8(x,_mm256_setr_epi8(3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12,3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12))
#define LANEIDX _mm256_setr_epi32(0,1,2,3,4,5,6,7)
#define LOADU(p) _mm256_loadu_si256((const __m256i*)(p))
#define STOREU(p,x) _mm256_storeu_si256((__m256i*)(p),x)
#define CMPZ(x) ((unsigned)_mm256_cmpeq_epi32_mask(x,_mm256_setzero_si256()))
"""
Z_MACROS="""#define V __m512i
#define ADD(a,b) _mm512_add_epi32(a,b)
#define XOR(a,b) _mm512_xor_si512(a,b)
#define SHR(x,n) _mm512_srli_epi32(x,n)
#define ROR(x,n) _mm512_ror_epi32(x,n)
#define T3(a,b,c,i) _mm512_ternarylogic_epi32(a,b,c,i)
#define SIG0V(x) T3(ROR(x,7),ROR(x,18),SHR(x,3),0x96)
#define SIG1V(x) T3(ROR(x,17),ROR(x,19),SHR(x,10),0x96)
#define BS0V(x) T3(ROR(x,2),ROR(x,13),ROR(x,22),0x96)
#define BS1V(x) T3(ROR(x,6),ROR(x,11),ROR(x,25),0x96)
#define CH(e,f,g) T3(e,f,g,0xCA)
#define MAJ(a,b,c) T3(a,b,c,0xE8)
#define SET1(x) _mm512_set1_epi32(x)
#define BSWAP(x) _mm512_shuffle_epi8(x,_mm512_broadcast_i32x4(_mm_setr_epi8(3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12)))
#define LANEIDX _mm512_setr_epi32(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)
#define LOADU(p) _mm512_loadu_si512((const void*)(p))
#define STOREU(p,x) _mm512_storeu_si512((void*)(p),x)
#define CMPZ(x) ((unsigned)_mm512_cmpeq_epi32_mask(x,_mm512_setzero_si512()))
"""
UNDEF="V ADD XOR AND OR SHR SHL ROR T3 SIG0V SIG1V BS0V BS1V CH MAJ SET1 BSWAP LANEIDX LOADU STOREU CMPZ".split()

KERNEL="""
/* ===== motor @NAME@ (@L@ serit) ===== */
#pragma GCC push_options
#pragma GCC target("@TARGET@")
@MACROS@
static inline void sched_@NAME@(const uint32_t *c, V nonce, V *KW){
@SCHED@
}
static inline V hash_@NAME@(const uint32_t *c, const VS *vs, const V *KW){
@HASH@
}
static uint64_t scan_@NAME@(const uint8_t *hdr, uint32_t start, uint64_t count, uint32_t mask, int M){
  uint32_t c[NC]; uint8_t hdrv[MAXM][76]; uint32_t ver[MAXM]; VS vs[MAXM];
  M=setup_versions(hdr,mask,M,hdrv,ver);
  prepare_shared(hdr,c); for(int j=0;j<M;j++) prepare_ver(hdrv[j],&vs[j]);
  V nv=ADD(SET1((int)start),LANEIDX); const V step=SET1(@L@); V KW[64];
  uint64_t hits=0;
  for(uint64_t base=0;base<count;base+=@L@){
    sched_@NAME@(c,BSWAP(nv),KW);
    for(int j=0;j<M;j++){
      unsigned mk=CMPZ(hash_@NAME@(c,&vs[j],KW));
      if(mk) for(int lane=0;lane<@L@;lane++) if(((mk>>lane)&1) && base+(uint64_t)lane<count)
        hits+=report_hit(hdrv[j],start+(uint32_t)(base+(uint64_t)lane),ver[j]);
    }
    nv=ADD(nv,step);
  }
  return hits;
}
static int test_@NAME@(void){
  uint64_t x=88172645463325252ULL; long checked=0,bad=0;
  for(int trial=0;trial<6;trial++){
    uint8_t hdr[76]; for(int i=0;i<76;i++){x^=x<<13;x^=x>>7;x^=x<<17;hdr[i]=(uint8_t)x;}
    uint32_t mask=0x1fffe000u,start=(uint32_t)x; int M=(trial%2)?16:8;
    uint32_t c[NC]; uint8_t hdrv[MAXM][76]; uint32_t ver[MAXM]; VS vs[MAXM];
    M=setup_versions(hdr,mask,M,hdrv,ver); prepare_shared(hdr,c); for(int j=0;j<M;j++) prepare_ver(hdrv[j],&vs[j]);
    V KW[64];
    for(uint32_t base=0;base<4096;base+=@L@){
      uint32_t ns[@L@]; for(int l=0;l<@L@;l++) ns[l]=start+base+l;
      sched_@NAME@(c,BSWAP(LOADU(ns)),KW);
      for(int j=0;j<M;j++){
        uint32_t out[@L@]; STOREU(out,hash_@NAME@(c,&vs[j],KW));
        for(int l=0;l<@L@;l++){ uint32_t s[8]; scalar_hash(hdrv[j],ns[l],s); checked++; if(s[7]!=out[l]) bad++; }
      }
    }
  }
  if(bad){ printf("%s: HATA checked=%ld bad=%ld\\n","@NAME@",checked,bad); return 1; }
  printf("%s: OK checked=%ld\\n","@NAME@",checked); return 0;
}
@UNDEFS@
#pragma GCC pop_options
"""
def kernel(name,L,target,macros,maj_mode):
    r=build(maj_mode)
    t=KERNEL
    for a,b in [("@NAME@",name),("@L@",str(L)),("@TARGET@",target),("@MACROS@",macros.rstrip()),("@SCHED@",r['sched']),("@HASH@",r['hash']),
                ("@UNDEFS@","\n".join(f"#undef {u}" for u in UNDEF))]:
        t=t.replace(a,b)
    return t,r

def main():
    skel=open(sys.argv[1]).read()
    k2,r2=kernel("avx2",8,"avx2",AVX2_MACROS,False)
    kv,rv=kernel("avx512vl",8,"avx2,avx512f,avx512vl",VL_MACROS,True)
    kz,rz=kernel("avx512",16,"avx2,avx512f,avx512bw,avx512vl",Z_MACROS,True)
    assert r2['prep']==rv['prep']==rz['prep'] and r2['nc']==rv['nc']==rz['nc']
    prep=f"#define NC {r2['nc']}\n"
    out=skel.replace("/*@NC@*/",prep).replace("/*@PREPARE@*/",r2['prep']).replace("/*@KERNELS@*/",k2+kv+kz)
    sys.stdout.write(out)
main()
