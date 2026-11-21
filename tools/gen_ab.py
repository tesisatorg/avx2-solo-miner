# sha256d AVX2 8-way + overt AsicBoost (version rolling): mesaj genisletmesi (schedule) bir kez, M version icin paylasilir
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

sl=[];vlA=[];vlB=[];cur=vlA;nc=19;vn=0
def newc(expr):
    global nc
    i=nc;nc+=1;sl.append(f"    c[{i}] = {expr};");return ('c',i)
def sx(x): return f"0x{x[1]:08x}u" if x[0]=='i' else f"c[{x[1]}]"
def vx(x):
    if x[0]=='v': return x[1]
    if x[0]=='k': return f"KW[{x[1]}]"
    return f"_mm256_set1_epi32((int){sx(x)})"
def emit_v(expr):
    global vn
    n=f"v{vn}";vn+=1;cur.append(f"    V {n} = {expr};");return ('v',n)
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
def kwof2(i,w):  # 2. hash (vektor/skaler)
    if w[0]!='v': return sadd(('i',K[i]),w)
    return emit_v(f"ADD({w[1]},_mm256_set1_epi32((int)0x{K[i]:08x}u))")
def rnd(m,i,kw,bc,pre,skip_a=False):
    a,b,c,d,e,f,g,h=m
    cur.append(f"    V t_{pre}{i} = ADD(ADD(ADD({h},BS1V({e})),CH({e},{f},{g})),{vx(kw)});")
    cur.append(f"    {d} = ADD({d},t_{pre}{i});")
    if skip_a: return [h,a,b,c,d,e,f,g],None
    cur.append(f"    V ab_{pre}{i} = XOR({a},{b});")
    cur.append(f"    {h} = ADD(ADD(t_{pre}{i},BS0V({a})),XOR({b},AND(ab_{pre}{i},{bc})));")
    return [h,a,b,c,d,e,f,g],f"ab_{pre}{i}"

# ===== PART A: 1. hash 2. blok mesaj genisletmesi (versiyondan bagimsiz, nonce'a bagli) -> KW[] =====
cur=vlA
cur.append("    V nonce_w3 = nonce;")
w=[('c',8),('c',9),('c',10),('v','nonce_w3'),('i',0x80000000)]+[('i',0)]*10+[('i',640)]
kwref={}
cur.append(f"    KW[3] = ADD(nonce_w3,_mm256_set1_epi32((int)0x{K[3]:08x}u));");kwref[3]=('k',3)
for i in range(4,16): kwref[i]=sadd(('i',K[i]),w[i])
for i in range(16,64):
    wnext(w,i)
    if w[i][0]=='v':
        cur.append(f"    KW[{i}] = ADD({w[i][1]},_mm256_set1_epi32((int)0x{K[i]:08x}u));");kwref[i]=('k',i)
    else: kwref[i]=sadd(('i',K[i]),w[i])

# ===== PART B: versiyon basina turlar =====
cur=vlB
for k,n in enumerate("abcdefgh"): cur.append(f"    V {n}1 = _mm256_set1_epi32((int)vs->st3[{k}]);")
cur.append("    V bc1 = XOR(b1,c1);")
m=[f"{n}1" for n in "abcdefgh"];bc="bc1"
for i in range(3,64): m,bc=rnd(m,i,kwref[i],bc,"p")
dig=[emit_v(f"ADD({m[k]},_mm256_set1_epi32((int)vs->mid[{k}]))") for k in range(8)]
w2=dig+[('i',0x80000000)]+[('i',0)]*6+[('i',256)]
T1c=(IV[7]+B1i(IV[4])+chi(IV[4],IV[5],IV[6])+K[0])&M32
T2c=(B0i(IV[0])+maji(IV[0],IV[1],IV[2]))&M32
cur.append(f"    V t_q0 = ADD({w2[0][1]},_mm256_set1_epi32((int)0x{T1c:08x}u));")
cur.append(f"    V a2 = ADD(t_q0,_mm256_set1_epi32((int)0x{T2c:08x}u));")
cur.append(f"    V e2 = ADD(t_q0,_mm256_set1_epi32((int)0x{IV[3]:08x}u));")
for n,k in zip("bcdfgh",[0,1,2,4,5,6]): cur.append(f"    V {n}2 = _mm256_set1_epi32((int)0x{IV[k]:08x}u);")
cur.append(f"    V bc2 = _mm256_set1_epi32((int)0x{IV[0]^IV[1]:08x}u);")
m=["a2","b2","c2","d2","e2","f2","g2","h2"];bc="bc2"
for i in range(1,61):
    if i>=16: wnext(w2,i)
    kw=kwof2(i,w2[i]);m,bc=rnd(m,i,kw,bc,"q",skip_a=(i>=57))
cur.append(f"    return ADD({m[4]},_mm256_set1_epi32((int)0x{IV[7]:08x}u));")

open("gen_nc.inc","w").write(f"#define NC {nc}\n")
open("gen_prepare.inc","w").write("\n".join(sl)+"\n")
open("gen_sched.inc","w").write("\n".join(vlA)+"\n")
open("gen_hash.inc","w").write("\n".join(vlB)+"\n")
print("skaler:",len(sl),"schedule satir:",len(vlA),"tur satir:",len(vlB),"NC",nc)
