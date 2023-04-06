import java.math.BigInteger;

public class Main {
    public static void main(String[] str) {
        /* instantiating an object of Paillier cryptosystem*/
        Paillier paillier = new Paillier();
        /* instantiating two plaintext msgs*/
        BigInteger m1 = new BigInteger("4");
        BigInteger m2 = new BigInteger("7");
        /* encryption*/
        BigInteger em1 = paillier.Encryption(m1);
        BigInteger em2 = paillier.Encryption(m2);
        /* printout encrypted text*/
        System.out.println("Original number 1: " + m1);
        System.out.println("Original number 2: " + m2);
        System.out.println("Encrypted number 1: " + em1);
        System.out.println("Encrypted number 2: " + em2);
        /* printout decrypted text */
        System.out.println("Decrypted number 1: " + paillier.Decryption(em1).toString());
        System.out.println("Decrypted number 2: " + paillier.Decryption(em2).toString());

        /* test homomorphic properties -> D(E(m1)*E(m2) mod n^2) = (m1 + m2) mod n */
        BigInteger product_em1em2 = em1.multiply(em2).mod(paillier.nsquare);
        BigInteger sum_m1m2 = m1.add(m2).mod(paillier.n);
        System.out.println("Original sum: " + sum_m1m2);
        System.out.println("Decrypted sum: " + paillier.Decryption(product_em1em2).toString());

        /* test homomorphic properties -> D(E(m1)^m2 mod n^2) = (m1*m2) mod n */
        BigInteger expo_em1m2 = em1.modPow(m2, paillier.nsquare);
        BigInteger prod_m1m2 = m1.multiply(m2).mod(paillier.n);
        System.out.println("Original multiply: " + prod_m1m2);
        System.out.println("Decrypted multiply: " + paillier.Decryption(expo_em1m2).toString());
    }
}