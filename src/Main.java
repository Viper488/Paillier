import java.math.BigInteger;

public class Main {
    public static void main(String[] str) {
        Paillier paillier = new Paillier(3072, 64);
        BigInteger n1 = new BigInteger("1337"), n2 = new BigInteger("7452");
        BigInteger eN1 = paillier.Encryption(n1), eN2 = paillier.Encryption(n2);

        System.out.println("Original number 1: " + n1 + ", Decrypted number 1: " + paillier.Decryption(eN1)
                + " , Encrypted number 1: " + eN1);
        System.out.println("Original number 2: " + n2 + ", Decrypted number 2: " + paillier.Decryption(eN2)
                + " , Encrypted number 2: " + eN2);

        System.out.println("\nPartial homomorphic trials");
        System.out.println("\nAddition of two plaintext");
        BigInteger eN1eN2 = eN1.multiply(eN2).mod(paillier.nsquare);
        BigInteger sum_m1m2 = n1.add(n2).mod(paillier.n);
        System.out.println("Decrypted sum: " + paillier.Decryption(eN1eN2));
        System.out.println("Original sum: " + sum_m1m2);

        System.out.println("\nMultiplication of a ciphertext by a plaintext number");
        BigInteger eN1N2 = eN1.modPow(n2, paillier.nsquare);
        BigInteger N1N2 = n1.multiply(n2).mod(paillier.n);
        System.out.println("Decrypted multiply: " + paillier.Decryption(eN1N2));
        System.out.println("Original multiply: " + N1N2);
    }
}