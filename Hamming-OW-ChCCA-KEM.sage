import numpy as np
import random
import hashlib

def generate_fixed_hamming_weight_vector_from_seed(field_size, lengths, weight, seed):
    random.seed(seed)
    F.<b> = GF(field_size, modulus='primitive')
    vector = zero_vector(GF(field_size),lengths)
    non_zero_indices = random.sample(range(lengths), k=weight)
    #non_zero_indices = np.random.choice(lengths, weight, replace=False)
    for i in non_zero_indices:
        vector[i] = b^randint(0,field_size-2)  # GF(2).ngens()
    return vector

def generate_fixed_hamming_weight_vector(field_size, lengths, weight):
    F.<b> = GF(field_size, modulus='primitive')
    vector = zero_vector(GF(field_size),lengths)
    non_zero_indices = random.sample(range(lengths), k=weight)
    for i in non_zero_indices:
        vector[i] = b^randint(0,field_size-2)  # GF(2).ngens()
    return vector
 
def generate_fixed_hamming_weight_matrix(field_size, rows, cols, weight): # rows \times columns matrix, the cloumn weight is weight
    F.<b> = GF(field_size, modulus='primitive')
    Matrix = zero_matrix(GF(field_size),rows, cols)
    for col in range(cols):
        non_zero_indices = random.sample(range(rows), k=weight)
        for i in non_zero_indices:
            Matrix[i, col] = b^randint(0,field_size-2)  
    return Matrix

def Oracle_G(Finite_Size, RHO_Length, x_Length, x_0_Length, Seed):
    set_random_seed(Seed)
    F = GF(Finite_Size)
    RHO = random_vector(GF(Finite_Size),RHO_Length)
    x = random_vector(F,x_Length)
    x_0 = random_vector(F,x_0_Length)
    x_1 = random_vector(F,x_0_Length)
    return RHO, x, x_0, x_1

def Vector_to_String(Vector):
    return "".join(map(str,Vector))

def String_to_Vector(Field_Size, String):
    return vector(GF(Field_Size),String)

def hash_bindigest_to_binary(text, hash_type='sha256', binary_length=256):
    h = hashlib.new(hash_type)
    h.update(text.encode('utf-8'))
    digest_bytes = h.digest()
    return ''.join(f'{byte:08b}' for byte in digest_bytes)[:binary_length]  


def hash_hexdigest_to_binary(text, hash_type='sha256', binary_length=256):
    h = hashlib.new(hash_type)
    h.update(text.encode('utf-8'))
    digest_bytes = h.hexdigest()
    return ''.join(f'{int(byte,16):04b}' for byte in digest_bytes)[:binary_length] 


# Setup
def KEM_Setup(q,k,n):
    return random_matrix(GF(q),k,n)

# Key Generation
def KEM_KGen(Para):
    E_0 = generate_fixed_hamming_weight_matrix(q, n, L, w_1)
    S_0 = Para* E_0
    #E_1 = generate_fixed_hamming_weight_matrix(q, n, L, w_1)
    S_1 = random_matrix(GF(q),k,L)
    return (S_0, S_1), (E_0, 0)

# Encapsulation
def KEM_Encap(Para, Public_Key0, Public_Key1):
    R = random_vector(GF(q),lamda)
    R_to_Sring = Vector_to_String(R)
    g = Oracle_G(q, lamda, k, m, R_to_Sring)
    g0_to_Sring = Vector_to_String(g[0])
    e = generate_fixed_hamming_weight_vector_from_seed(q, n, w_2, g0_to_Sring)
    y = g[1] * Para + e
    hat_x_0 = g[1] * Public_Key0 + g[2] * G
    hat_x_1 = g[1] * Public_Key1 + g[3] * G
    text0 = Vector_to_String(y) + Vector_to_String(hat_x_0) + Vector_to_String(g[2])
    C_0 = String_to_Vector(q,hash_bindigest_to_binary(text0, hash_type='sha256', binary_length=lamda)) +  R
    text1 = Vector_to_String(y) + Vector_to_String(hat_x_1) + Vector_to_String(g[3])
    C_1 = String_to_Vector(q,hash_bindigest_to_binary(text1, hash_type='sha256', binary_length=lamda)) +  R
    return C_0, hat_x_0, C_1, hat_x_1, y


# Dencapsulation
def KEM_Decap(Para, Private_Key, Ciphertext):
    ct = Ciphertext; sk = Private_Key[0]
    errored_codeword = ct[1] - ct[4] * sk
    Message1 = D.decode_to_message(errored_codeword)
    Message = vector(GF(q**d), Message1.padded_list(RSCodes.dimension()))
    text0 = Vector_to_String(ct[4]) + Vector_to_String(ct[1]) + Vector_to_String(Message)
    RR = String_to_Vector(q,hash_bindigest_to_binary(text0, hash_type='sha256', binary_length=lamda)) + ct[0]
    RR_to_Sring = Vector_to_String(RR)
    gg = Oracle_G(q, lamda, k, m, RR_to_Sring)
    gg0_to_Sring = Vector_to_String(gg[0])
    ee = generate_fixed_hamming_weight_vector_from_seed(q, n, w_2, gg0_to_Sring)
    hhat_x_1 = gg[1] * Public_Key1 + gg[3] * G
    text1 = Vector_to_String(ct[4]) + Vector_to_String(hhat_x_1) + Vector_to_String(gg[3])
    Bool1 = (RR == String_to_Vector(q,hash_bindigest_to_binary(text1, hash_type='sha256', binary_length=lamda)) + ct[2])
    Bool2 = (ct[4] == gg[1] * Para + ee)
    Bool3 = (Message == gg[2])
    Bool4 = (hhat_x_1 == ct[3])
    if Bool1 and Bool2 and Bool3 and Bool4:
        return RR
    return 0



(lamda,q,n,k,L,m,w_1,w_2,d) = (128,2,80000,40000,4095,128,200,200,12)
code_length = q**d-1
dimension = m
RSCodes = codes.ReedSolomonCode(GF(q**d), code_length, dimension)
G = RSCodes.generator_matrix()
D = codes.decoders.GRSBerlekampWelchDecoder(RSCodes)


%time Para = KEM_Setup(q,k,n)

%time Key = KEM_KGen(Para)
Public_Key0 = Key[0][0]; Public_Key1 = Key[0][1]; Private_Key = Key[1]
%time Ciphertext = KEM_Encap(Para, Public_Key0, Public_Key1)

%time R = KEM_Decap(Para, Private_Key,Ciphertext)
