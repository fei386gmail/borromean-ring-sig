package com.weavechain.sig;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.List;

@Getter
@AllArgsConstructor
public class BorromeanRingSigParams {

    private final List<List<ECPoint>> ringKeys;

    private final List<byte[]> knownPrivateKeys;

    private final List<Integer> ringIndexes;
}