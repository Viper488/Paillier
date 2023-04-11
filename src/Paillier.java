import java.math.*;
import java.util.*;

/**
 * Paillier Cryptosystem
 * @author Artur Hamernik
 */
public class Paillier {
    private BigInteger lambda;
    /**
     * n = p * q
     */
    public BigInteger n;
    /**
     * nsquare = n*n
     */
    public BigInteger nsquare;
    /**
     * g - a random integer g in Z*(n^2) = {k<={0,1,...,n^2-1}: gcd(k, n^2) = 1}
     */
    private BigInteger g;
    /**
     * u - a modular multiplicative inverse
     */
    private BigInteger u;
    /**
     * number of bits of modulus
     */
    private int bitLength;

    /**
     * Constructs an instance of the Paillier Cryptosystem
     */
    public Paillier() {}
    public Paillier(int bitLength, int certainty) {
        generateKeys(bitLength, certainty);
    }

    /**
     * Sets up the public key and private key.
     * @param bitLength number of bits of modulus.
     * @param certainty The probability that the new BigInteger represents a prime number will exceed (1 - 2^(-certainty)).
     *                  The execution time of this constructor is proportional to the value of this parameter.
     */
    public void generateKeys(int bitLength, int certainty) {
        this.bitLength = bitLength;
        /*
         * Calculate u until [u * L(g^lambda mod n^2)] mod n = 1
         */
        do {
            /*
             * Pick two random integers p and q. Pick again until gcd(p*q,(p-1)*(q-1)) = 1
             *
             * p, q - prime, large, randomly and independently chosen
             * lambda = lcm(p-1, q-1) = (p-1)*(q-1)/gcd(p-1, q-1). - least common multiple of p-1 nad q-1
             */
            BigInteger p, q;
            do {
                p = new BigInteger(this.bitLength / 2, certainty, new Random());
                q = new BigInteger(this.bitLength / 2, certainty, new Random());
            } while (!p.multiply(q).gcd(p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE))).equals(BigInteger.ONE));

            n = p.multiply(q);
            lambda = lcm(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE));
            nsquare = n.multiply(n);

            /*
             * Pick random g from Z*(n^2) = {k<={0,1,...,n^2-1}: gcd(k, n^2) = 1}. Check if g belongs to our Z*
             * which means gcd(g,n^2) = 1
             */
            g = numberInN();

            /*
             * Calculate u - modular multiplicative inverse
             */
            u = L(g.modPow(lambda, nsquare)).modInverse(n);
        } while (!u.multiply(L(g.modPow(lambda, nsquare))).mod(n).equals(BigInteger.ONE));
    }

    /**
     * Least common multiple
     * @param a
     * @param b
     * @return
     */
    private BigInteger lcm(BigInteger a, BigInteger b) {
        return a.multiply(b).abs().divide(a.gcd(b));
    }

    /**
     * L function
     * @param x
     * @return
     */
    private BigInteger L(BigInteger x) {
        return x.subtract(BigInteger.ONE).divide(n);
    }

    private BigInteger numberInN() {
        BigInteger number;
        do {
            number = new BigInteger(bitLength / 2, new Random());
        } while (!number.gcd(nsquare).equals(BigInteger.ONE));

        return number;
    }
    /**
     * Encrypts plaintext m. ciphertext c = g^m * r^n mod n^2. This function automatically generates random input r (to help with encryption).
     * @param m plaintext as a BigInteger
     * @return ciphertext as a BigInteger
     */
    public BigInteger Encryption(BigInteger m) {
        if(!(m.intValue() < n.intValue())) {
            System.err.println("M must be lesser than N");
            System.exit(0);
        }
        BigInteger r;
        do {
            r = numberInN();
        } while (!(r.intValue() < n.intValue()));

        return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare));
    }

    /**
     * Decrypts ciphertext c. plaintext m = L(c^lambda mod n^2) * u mod n, where u = (L(g^lambda mod n^2))^(-1) mod n.
     * @param c ciphertext as a BigInteger
     * @return plaintext as a BigInteger
     */
    public BigInteger Decryption(BigInteger c) {
        return L(c.modPow(lambda, nsquare)).multiply(u).mod(n);
    }
}