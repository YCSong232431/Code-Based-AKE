

import numpy as np
import random
import hashlib

(q,d,n,k,L,m,w_1,w_2,lamda) = (2,89,2*191,191,88,7,5,4,128) 

Fqm = GF(q**d)
P1  = GF(q)['XX'].irreducible_element(k, algorithm="minimal_weight")
P.<XX> = Fqm[]
R.<X> = P.quotient(P1)

Frob = Fqm.frobenius_endomorphism()
S = OrePolynomialRing(Fqm, Frob, 'x')

def random_small_vector_genenration(Extension, Length, Weight):
    B = matrix(Fqm.base_ring(), Weight, Extension, 0)
    while B.rank() != Weight:
        B = random_matrix(Fqm.base_ring(),Weight, Extension)
    C = matrix(Fqm.base_ring(), Length, Extension,0)
    while C.rank() != Weight:
        C = random_matrix(Fqm.base_ring(), Length, Weight) * B
    return vector(Fqm,[C[i] for i in range(Length)])


def random_small_vector_generation_from_seed(Extension, Length, Weight, Seed):
    set_random_seed(Seed)   
    return random_small_vector_genenration(Extension, Length, Weight)

def random_small_blockwise_vector_generation_from_seed(Extension, Length1, Length2, Weight1, Weight2, Seed):
    set_random_seed(Seed)   
    e1 = random_small_vector_generation_from_seed(Extension, Length1, Weight1, Seed)
    e2 = random_small_vector_generation_from_seed(Extension, Length2, Weight2, Seed)
    return vector(Fqm,list(e1)+list(e2))

def ideal_matrix(R_Element,Times):
    Length = len(R_Element.list())
    list1 = []
    for i in range(Times):
        c = list(X**i * R_Element)
        list1.append(c)
    return matrix(Times,Length,list1)


def Vector_to_String(Vector):
    return "".join(map(str,Vector))

def String_to_Vector(Field_Size, String):
    return vector(GF(Field_Size),String)


def hash_bindigest_to_binary(text, hash_type='sha256', binary_length=256):  
    h = hashlib.new(hash_type) 
    h.update(text.encode('utf-8'))
    digest_bytes = h.digest()   
    return ''.join(f'{byte:08b}' for byte in digest_bytes)[:binary_length]  

def Oracle_G(RHO_Length, x_Length, x_0_Length, Seed):
    set_random_seed(Seed)
    RHO = random_vector(Fqm.base_ring(),RHO_Length)
    x = random_vector(Fqm,x_Length)
    x_0 = random_vector(Fqm,x_0_Length)
    x_1 = random_vector(Fqm,x_0_Length)
    return RHO, x, x_0, x_1

def Encoding_Gabidulin(Message, Gabidulin_Support):
    f = S(Message.list())  # The message polynomial 
    return vector(f.multi_point_evaluation(Gabidulin_Support))

def Decoding_Gabidulin(Noisy_Word, Gabidulin_Support,Code_Length, Code_Dimension,Weight): 
    g_monomials = [Gabidulin_Support[i]**(q**j) for i in range(Code_Length) for j in range(Code_Dimension + Weight)] 
    SC1 = matrix(Fqm,Code_Length, Code_Dimension+Weight, g_monomials) 
    y_monomials = [Noisy_Word[i]**(q**j) for i in range(Code_Length) for j in range(Weight+1)] 
    SC2 = matrix(Fqm,Code_Length, Weight+1, y_monomials) 
    SC = block_matrix(Fqm,1,2,[SC1,SC2])
    Solution = SC.right_kernel_matrix().list()  
    N = S(Solution[0 : Code_Dimension+Weight])
    V_vector = vector(Solution[Code_Dimension+Weight : Code_Dimension+2*Weight+1])
    V = S(list(-V_vector))
    ff,re = N.left_quo_rem(V)
    return vector(ff.padded_list(Code_Dimension))

# Setup
def KEM_Setup():
    a_0 = R.random_element()
    a_1 = R.random_element()
    A_0 = ideal_matrix(a_0, k).transpose()
    A_1 = ideal_matrix( a_1, k).transpose()
    A = block_matrix(1,2,[A_0, A_1])
    return a_0, a_1, A


# Key Generation
def KEM_KGen(Para0, Para1):
    e_0_prime = list(random_small_vector_genenration(d,k,w_1))
    e_0 = R(e_0_prime)
    e_1_prime = list(random_small_vector_genenration(d,k,w_2))
    e_1 = R(e_1_prime)
    E_0_0 = ideal_matrix(e_0, L).transpose()
    E_0_1 = ideal_matrix(e_1, L).transpose()
    E_0 = block_matrix(2,1,[E_0_0, E_0_1])
    s = Para0 * e_0 + Para1 * e_1 
    S_0 = ideal_matrix(s, L).transpose()
    S_1 = ideal_matrix(R.random_element(), L).transpose()
    return (S_0, S_1), (E_0, 0)

# Encapsulation
def KEM_Encap(Para, Public_Key0, Public_Key1):
    R = random_vector(GF(2),lamda)
    R_to_Sring = Vector_to_String(R)
    g = Oracle_G(lamda, k, m, R_to_Sring)
    g0_to_Sring = Vector_to_String(g[0])
    e = random_small_blockwise_vector_generation_from_seed(d, k, k, w_2,w_1, g0_to_Sring)
    y = g[1] * Para + e
    hat_x_0 = g[1] * Public_Key0 + Encoding_Gabidulin(g[2], Code_Support) 
    hat_x_1 = g[1] * Public_Key1 + Encoding_Gabidulin(g[3], Code_Support) 
    text0 = Vector_to_String(y) + Vector_to_String(hat_x_0) + Vector_to_String(g[2])
    C_0 = String_to_Vector(q,hash_bindigest_to_binary(text0, hash_type='sha256', binary_length=lamda)) +  R
    text1 = Vector_to_String(y) + Vector_to_String(hat_x_1) + Vector_to_String(g[3])
    C_1 = String_to_Vector(q,hash_bindigest_to_binary(text1, hash_type='sha256', binary_length=lamda)) +  R
    return C_0, hat_x_0, C_1, hat_x_1, y

# Decapsulation
def KEM_Decap(Para, Private_Key, Ciphertext):
    ct = Ciphertext; sk = Private_Key[0]
    errored_codeword = ct[1] - ct[4] * sk
    Message = Decoding_Gabidulin(errored_codeword, Code_Support,L, m, 2*w_1*w_2)  
    text0 = Vector_to_String(ct[4]) + Vector_to_String(ct[1]) + Vector_to_String(Message)
    RR = String_to_Vector(q,hash_bindigest_to_binary(text0, hash_type='sha256', binary_length=lamda)) + ct[0]
    RR_to_Sring = Vector_to_String(RR)
    gg = Oracle_G(lamda, k, m, RR_to_Sring)
    gg0_to_Sring = Vector_to_String(gg[0])
    ee = random_small_blockwise_vector_generation_from_seed(d,k, k, w_2, w_1, gg0_to_Sring)
    hhat_x_1 = gg[1] * Public_Key1 + Encoding_Gabidulin(gg[3], Code_Support) 
    text1 = Vector_to_String(ct[4]) + Vector_to_String(hhat_x_1) + Vector_to_String(gg[3])
    Bool1 = (RR == String_to_Vector(q,hash_bindigest_to_binary(text1, hash_type='sha256', binary_length=lamda)) + ct[2])
    Bool2 = (ct[4] == gg[1] * Para + ee)
    Bool3 = (Message == gg[2])
    Bool4 = (hhat_x_1 == ct[3])
    if Bool1 and Bool2 and Bool3 and Bool4:
        return RR
    return 0

Code_Support = random_small_vector_genenration(d, L, L)

%time Para = KEM_Setup()

Para0 = Para[0]; Para1 = Para[1]; Para2 = Para[2]

%time Key = KEM_KGen(Para0, Para1)

Public_Key0 = Key[0][0]; Public_Key1 = Key[0][1]; Private_Key = Key[1]

%time Ciphertext = KEM_Encap(Para2, Public_Key0, Public_Key1)

%time Key_R = KEM_Decap(Para2, Private_Key, Ciphertext)
