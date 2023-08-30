package com.weavechain.sig;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECPoint;

public class BorromeanRingSig {

    private final BorromeanRingSigParams params;

    private final X9ECParameters curveParams;

    private final Random rng;

    private static final String DEFAULT_HASH_FN = "SHA-256";

    private static final String CURVE = "secp256k1";

    private static ThreadLocal<MessageDigest> DIGEST;

    public BorromeanRingSig(BorromeanRingSigParams params) {
        this(params, new SecureRandom(), DEFAULT_HASH_FN);
    }

    public BorromeanRingSig(BorromeanRingSigParams params, Random rng, String hashFunction) {
        this.params = params;
        this.rng = rng;

        curveParams = CustomNamedCurves.getByName(CURVE);

        DIGEST = ThreadLocal.withInitial(() -> {
            try {
                return MessageDigest.getInstance(hashFunction);
            } catch (Exception e) {
                return null;
            }
        });
    }

    private static byte[] serialize(ECPoint p) {
        byte[] compressed = p.getEncoded(false);
        byte[] result = new byte[compressed.length - 1];
        System.arraycopy(compressed, 1, result, 0, result.length);
        return result;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private BigInteger random(BigInteger order) {
        return new BigInteger(order.bitLength(), rng).mod(order);
    }

    private static byte[] toBytes(BigInteger val) {
        byte[] bytes = val.toByteArray();
        if (bytes.length == 33) {
            return Arrays.copyOfRange(bytes, 1, 33);
        } else if (bytes.length < 32) {
            byte[] out = new byte[32];
            System.arraycopy(bytes, 0, out, 32 - bytes.length, bytes.length);
            return out;
        } else {
            return bytes;
        }
    }

    private static byte[] trim(byte[] input, int len) {
        return input.length > len ?  Arrays.copyOfRange(input, 0, 32) : input;
    }

    private static byte[] hash(byte[] toHash) {
        MessageDigest digest = DIGEST.get();
        digest.reset();
        digest.update(toHash);
        return trim(digest.digest(), 32);
    }

    private BigInteger hash(String m, byte[] p, int i, int j) {
        byte[] bm = m.getBytes(StandardCharsets.UTF_8);
        byte[] bi = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(i).array();
        byte[] bj = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(j).array();

        byte[] toSign = new byte[bm.length + p.length + bi.length + bj.length];
        System.arraycopy(bm, 0, toSign, 0, bm.length);
        System.arraycopy(p, 0, toSign, bm.length, p.length);
        System.arraycopy(bi, 0, toSign, bm.length + p.length, bi.length);
        System.arraycopy(bj, 0, toSign, bm.length + p.length + bi.length, bj.length);

        return new BigInteger(1, hash(toSign));
    }

    public byte[] sign(String msg) {
        List<List<ECPoint>> ringKeys = params.getRingKeys();

        List<BigInteger> signatures = new ArrayList<>();
        ringKeys.forEach((r) -> {
            for (int j = 0; j < r.size(); j++) {
                signatures.add(null);
            }
        });

        byte[] toHash = new byte[0];
        List<BigInteger> k = new ArrayList<>();

        ECPoint G = curveParams.getG();
        BigInteger order = curveParams.getN();
        int dx = 0;
        for (int i = 0; i < params.getRingKeys().size(); i++) {
            List<ECPoint> pubKeys = ringKeys.get(i);

            k.add(random(order));
            ECPoint kiG = G.multiply(k.get(i));
            int idx = params.getRingIndexes().get(i);
            ECPoint e = kiG;

            int len = pubKeys.size();
            for (int j = idx + 1; j < len; j++) {
                BigInteger r = random(order);
                signatures.set(dx + j, r);
                BigInteger h = hash(msg, serialize(e), i, j);
                ECPoint a = G.multiply(signatures.get(dx + j));
                ECPoint b = pubKeys.get(j).multiply(h);

                e = a.add(b);
            }
            toHash = concat(toHash, serialize(e));
            dx += len;
        }
        
        toHash = concat(toHash, msg.getBytes());
        byte[] e0 = hash(toHash);

        dx = 0;
        for (int i = 0; i < params.getRingKeys().size(); i++) {
            List<ECPoint> pubKeys = ringKeys.get(i);

            int idx = params.getRingIndexes().get(i);
            BigInteger e = hash(msg, e0, i, 0);

            for (int j = 0; j < idx; j++) {
                BigInteger r = random(order);
                signatures.set(dx + j, r);
                ECPoint a = G.multiply(signatures.get(dx + j));
                ECPoint b = pubKeys.get(j).multiply(e);

                e = hash(msg, serialize(a.add(b)), i, j + 1);
            }
            BigInteger pk = new BigInteger(1, params.getKnownPrivateKeys().get(i));
            BigInteger s_ij = k.get(i).subtract(e.multiply(pk)).mod(order);
            signatures.set(dx + idx, s_ij);
            dx += pubKeys.size();
        }

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        try {
            os.write(e0);
            for (BigInteger it : signatures) {
                os.write(toBytes(it));
            }
        } catch (IOException e) {
            //ignore
        }

        return os.toByteArray();
    }

    public boolean verify(String msg, byte[] signature) {
        try {
            List<List<ECPoint>> ringKeys = params.getRingKeys();

            ByteArrayInputStream is = new ByteArrayInputStream(signature);

            byte[] toHash = new byte[0];
            byte[] e0 = new byte[32];
            if (is.read(e0) < 0) {
                return false;
            }

            ECPoint G = curveParams.getG();
            for (int i = 0; i < ringKeys.size(); i++) {
                List<ECPoint> pubKeys = ringKeys.get(i);
                int len = pubKeys.size();

                BigInteger e = hash(msg, e0, i, 0);
                for (int j = 0; j < len; j++) {
                    byte[] s = new byte[32];
                    if (is.read(s) < 0) {
                        return false;
                    }
                    ECPoint a = G.multiply(new BigInteger(1, s));
                    ECPoint b = pubKeys.get(j).multiply(e);
                    if (j < len - 1) {
                        e = hash(msg, serialize(a.add(b)), i, j + 1);
                    } else {
                        toHash = concat(toHash, serialize(a.add(b)));
                    }
                }
            }

            toHash = concat(toHash, msg.getBytes());
            return Arrays.equals(e0, hash(toHash));
        } catch (IOException e) {
            return false;
        }
    }

    public static void main(String[] args) {
        SecureRandom rng = new SecureRandom();

        byte[] pvk1 = new byte[32];
        byte[] pvk2 = new byte[32];
        byte[] pvk3 = new byte[32];
        byte[] pvk4 = new byte[32];

        byte[] pvk5 = new byte[32];
        byte[] pvk6 = new byte[32];
        byte[] pvk7 = new byte[32];

        rng.nextBytes(pvk1);
        rng.nextBytes(pvk2);
        rng.nextBytes(pvk3);
        rng.nextBytes(pvk4);
        rng.nextBytes(pvk5);
        rng.nextBytes(pvk6);
        rng.nextBytes(pvk7);

        X9ECParameters cv = CustomNamedCurves.getByName("secp256k1");
        ECPoint pub1 = cv.getG().multiply(new BigInteger(1, pvk1));
        ECPoint pub2 = cv.getG().multiply(new BigInteger(1, pvk2));
        ECPoint pub3 = cv.getG().multiply(new BigInteger(1, pvk3));
        ECPoint pub4 = cv.getG().multiply(new BigInteger(1, pvk4));

        ECPoint pub5 = cv.getG().multiply(new BigInteger(1, pvk5));
        ECPoint pub6 = cv.getG().multiply(new BigInteger(1, pvk6));
        ECPoint pub7 = cv.getG().multiply(new BigInteger(1, pvk7));

        List<ECPoint> ring1 = List.of(pub1, pub2, pub3, pub4);
        List<ECPoint> ring2 = List.of(pub5, pub6, pub7);
        List<List<ECPoint>> rings = List.of(ring1, ring2);

        List<byte[]> knownPrivateKeys = List.of(pvk1, pvk6);
        List<Integer> ringIndexes = List.of(0, 1);
        BorromeanRingSigParams params = new BorromeanRingSigParams(rings, knownPrivateKeys, ringIndexes);
        BorromeanRingSig sig = new BorromeanRingSig(params);

        String message = "zkp";
        byte[] signature = sig.sign(message);

        BorromeanRingSig sigCheck = new BorromeanRingSig(new BorromeanRingSigParams(rings, null, null));
        boolean check = sigCheck.verify(message, signature);
        System.out.println(check ? "Success" : "Fail");
    }
}