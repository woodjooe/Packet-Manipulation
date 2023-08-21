import random
import binascii


def coppersmith_short_pad(C1, C2, N, e = 3, eps = 1/25):
    P.<x, y> = PolynomialRing(Zmod(N))
    P2.<y> = PolynomialRing(Zmod(N))

    g1 = (x^e - C1).change_ring(P2)
    g2 = ((x + y)^e - C2).change_ring(P2)
 
    # Changes the base ring to Z_N[y] and finds resultant of g1 and g2 in x
    res = g1.resultant(g2, variable=x)

    # coppersmith's small_roots only works over univariate polynomial rings, so we 
    # convert the resulting polynomial to its univariate form and take the coefficients modulo N
    # Then we can call the sage's small_roots function and obtain the delta between m_1 and m_2.
    # Play around with these parameters: (epsilon, beta, X)
    roots = res.univariate_polynomial().change_ring(Zmod(N))\
        .small_roots(epsilon=eps)

    return roots[0]

def franklin_reiter(C1, C2, N, r, e=3):
    P.<x> = PolynomialRing(Zmod(N))
    equations = [x ^ e - C1, (x + r) ^ e - C2]
    g1, g2 = equations
    return -composite_gcd(g1,g2).coefficients()[0]


# I should implement something to divide the resulting message by some power of 2^i
def recover_message(C1, C2, N, e = 3):
    delta = coppersmith_short_pad(C1, C2, N)
    recovered = franklin_reiter(C1, C2, N, delta)
    return recovered
    
def composite_gcd(g1,g2):
    return g1.monic() if g2 == 0 else composite_gcd(g2, g1 % g2)

# Takes a long time for larger values and smaller epsilon
def test():

    N_E_C1_C2_file = open("N_E_C1_C2.txt", "rb")

    ''' N=0
     
    e = 3

    C1=0

    C2=0
    '''


    N = int.from_bytes(N_E_C1_C2_file.readline()[:-1])
    e = int.from_bytes(N_E_C1_C2_file.readline()[:-1])
    #N = N_E_C1_C2_file.readline()[:-1]
    #e = N_E_C1_C2_file.readline()[:-1]
    #C1 = N_E_C1_C2_file.readline()[:-1]
    #C2 = N_E_C1_C2_file.readline()[:-1]
    
    C1 = int.from_bytes(N_E_C1_C2_file.readline()[:-1])
    C2 = int.from_bytes(N_E_C1_C2_file.readline()[:-1])
    N_E_C1_C2_file.close()
    print(N)
    print(e)
    print(C1)
    print(C2)
    # Using eps = 1/125 is slooooowww
    Cop = coppersmith_short_pad(C1, C2, N, eps=0.015625)
    Plaintext = recover_message(C1, C2, N)
    print(Cop)
    print(Plaintext)
    
    Plain_file = open("Plain.txt", "w")
    Plain_file.write(Plaintext)
    Plain_file.close()
    
if __name__ == "__main__":
    test()
