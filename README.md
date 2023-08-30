## Borromean Ring Signatures

A pure Java implementation of a Borromean Ring Signature scheme.

This type of signature allows privacy preserving signing. It can be used in conjunction with zero-knowledge proofs to certify that somebody who is part of a certain group has a piece of data, without revealing the identity of the owner.

Part of [Weavechain](https://weavechain.com): The Layer-0 For Data

### Usage

#### Gradle Groovy DSL

```
implementation 'com.weavechain:borromean-ring-sig:1.0'
```

#### Gradle Kotlin DSL

```
implementation("com.weavechain:borromean-ring-sig:1.0")
```

##### Apache Maven

```xml
<dependency>
  <groupId>com.weavechain</groupId>
  <artifactId>borromean-ring-sig</artifactId>
  <version>1.0</version>
</dependency>
```

#### Sample

Generate a signature

```java
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
System.out.println(Arrays.toString(signature));
```

Verify a signature

```java
BorromeanRingSig sigCheck = new BorromeanRingSig(new BorromeanRingSigParams(rings, null, null));
boolean check = sigCheck.verify(message, signature);
System.out.println(check ? "Success" : "Fail");
```

#### Weavechain

Read more about Weavechain at [https://docs.weavechain.com](https://docs.weavechain.com)