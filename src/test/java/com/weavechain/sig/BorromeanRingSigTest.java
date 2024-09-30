package com.weavechain.sig;

import com.google.common.truth.Truth;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

public class BorromeanRingSigTest {

    @BeforeClass
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    protected void testRingSignature() throws Exception {
        SecureRandom rng = new SecureRandom();

        byte[] pvk1 = new byte[32];
        byte[] pvk2 = new byte[32];
        byte[] pvk3 = new byte[32];
        byte[] pvk4 = new byte[32];

        X9ECParameters cv = CustomNamedCurves.getByName("secp256k1");
        ECPoint pub1 = cv.getG().multiply(new BigInteger(1, pvk1));
        ECPoint pub2 = cv.getG().multiply(new BigInteger(1, pvk2));
        ECPoint pub3 = cv.getG().multiply(new BigInteger(1, pvk3));
        ECPoint pub4 = cv.getG().multiply(new BigInteger(1, pvk4));


        List<ECPoint> ring1 = new ArrayList<>();
        ring1.add(pub1);  ring1.add(pub2);  ring1.add(pub3);  ring1.add(pub4);
//                List.of(pub1, pub2, pub3, pub4);

        List<List<ECPoint>> rings = new ArrayList<>();
        rings.add(ring1);
//                List.of(ring1);

        List<byte[]> knownPrivateKeys1 = new ArrayList<>();
        knownPrivateKeys1.add(pvk2);
//                List.of(pvk2);
        List<Integer> ringIndexes1 = new ArrayList<>();
        ringIndexes1.add(1);
//                List.of(1);
        BorromeanRingSigParams params1 = new BorromeanRingSigParams(rings, knownPrivateKeys1, ringIndexes1);
        BorromeanRingSig sig1 = new BorromeanRingSig(params1);

        List<byte[]> knownPrivateKeys2 = new ArrayList<>();
        knownPrivateKeys2.add(pvk4);
//                List.of(pvk4);
        List<Integer> ringIndexes2 = new ArrayList<>();
        ringIndexes2.add(3);
//                List.of(3);
        BorromeanRingSigParams params2 = new BorromeanRingSigParams(rings, knownPrivateKeys2, ringIndexes2);
        BorromeanRingSig sig2 = new BorromeanRingSig(params1);

        String message = "zkp";
        byte[] signature1 = sig1.sign(message);
        byte[] signature2 = sig2.sign(message);

        BorromeanRingSig sigCheck = new BorromeanRingSig(new BorromeanRingSigParams(rings, null, null));
        boolean check1 = sigCheck.verify(message, signature1);
        Truth.assertThat(check1).isEqualTo(true);

        boolean check2 = sigCheck.verify(message, signature2);
        Truth.assertThat(check2).isEqualTo(true);
    }

    @Test
    protected void testMultipleRings() throws Exception {
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

        List<ECPoint> ring1 = new ArrayList<>();
        ring1.add(pub1);  ring1.add(pub2);  ring1.add(pub3);  ring1.add(pub4);
//        List.of(pub1, pub2, pub3, pub4);
        List<ECPoint> ring2 = new ArrayList<>();
        ring2.add(pub5);   ring2.add(pub6);   ring2.add(pub7);
//        List.of(pub5, pub6, pub7);
        List<List<ECPoint>> rings = new ArrayList<>();
        rings.add(ring1);  rings.add(ring2);
//                List.of(ring1, ring2);

        List<byte[]> knownPrivateKeys = new ArrayList<>();
        knownPrivateKeys.add(pvk1);   knownPrivateKeys.add(pvk6);
//                List.of(pvk1, pvk6);
        List<Integer> ringIndexes = new ArrayList<>();
        ringIndexes.add(0);   ringIndexes.add(1);
//                List.of(0, 1);
        BorromeanRingSigParams params = new BorromeanRingSigParams(rings, knownPrivateKeys, ringIndexes);
        BorromeanRingSig sig = new BorromeanRingSig(params);

        String message = "zkp";
        byte[] signature = sig.sign(message);

        BorromeanRingSig sigCheck = new BorromeanRingSig(new BorromeanRingSigParams(rings, null, null));
        boolean check = sigCheck.verify(message, signature);
        Truth.assertThat(check).isEqualTo(true);
    }
}
