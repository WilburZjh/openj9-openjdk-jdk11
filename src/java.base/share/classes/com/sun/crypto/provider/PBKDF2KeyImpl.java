/*
 * Copyright (c) 2005, 2019, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */
/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2022, 2023 All Rights Reserved
 * ===========================================================================
 */

package com.sun.crypto.provider;

import java.io.ObjectStreamException;
import java.lang.ref.Reference;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Locale;
import java.security.MessageDigest;
import java.security.KeyRep;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;

import jdk.crypto.jniprovider.NativeCrypto;
import jdk.internal.ref.CleanerFactory;

import openj9.internal.security.RestrictedSecurity;

/**
 * This class represents a PBE key derived using PBKDF2 defined
 * in PKCS#5 v2.0. meaning that
 * 1) the password must consist of characters which will be converted
 *    to bytes using UTF-8 character encoding.
 * 2) salt, iteration count, and to be derived key length are supplied
 *
 * @author Valerie Peng
 *
 */
final class PBKDF2KeyImpl implements javax.crypto.interfaces.PBEKey {

    static final long serialVersionUID = -2234868909660948157L;

    private static final NativeCrypto nativeCrypto = NativeCrypto.getNativeCrypto();
    private static final boolean nativeCryptTrace = NativeCrypto.isTraceEnabled();

    /* 
     * The property 'jdk.nativePBE2' is used to control enablement of the native
     * PBE implementation.
     */
    private static final boolean useNativePBES2 = NativeCrypto.isAlgorithmEnabled("jdk.nativePBES2", "PBKDF2KeyImpl");

    private char[] passwd;
    private byte[] salt;
    private int iterCount;
    private byte[] key;

    private Mac prf;

    private static byte[] getPasswordBytes(char[] passwd) {
        Charset utf8 = Charset.forName("UTF-8");
        CharBuffer cb = CharBuffer.wrap(passwd);
        ByteBuffer bb = utf8.encode(cb);

        int len = bb.limit();
        byte[] passwdBytes = new byte[len];
        bb.get(passwdBytes, 0, len);

        return passwdBytes;
    }

    /**
     * Creates a PBE key from a given PBE key specification.
     *
     * @param keySpec the given PBE key specification
     * @param prfAlgo the given PBE key algorithm
     */
    PBKDF2KeyImpl(PBEKeySpec keySpec, String prfAlgo)
        throws InvalidKeySpecException {
        char[] passwd = keySpec.getPassword();
        if (passwd == null) {
            // Should allow an empty password.
            this.passwd = new char[0];
        } else {
            this.passwd = passwd.clone();
        }
        // Convert the password from char[] to byte[]
        byte[] passwdBytes = getPasswordBytes(this.passwd);
        // remove local copy
        if (passwd != null) Arrays.fill(passwd, '\0');

        try {
            this.salt = keySpec.getSalt();
            if (salt == null) {
                throw new InvalidKeySpecException("Salt not found");
            }
            this.iterCount = keySpec.getIterationCount();
            if (iterCount == 0) {
                throw new InvalidKeySpecException("Iteration count not found");
            } else if (iterCount < 0) {
                throw new InvalidKeySpecException("Iteration count is negative");
            }
            int keyLength = keySpec.getKeyLength();
            if (keyLength == 0) {
                throw new InvalidKeySpecException("Key length not found");
            } else if (keyLength < 0) {
                throw new InvalidKeySpecException("Key length is negative");
            }
            if (RestrictedSecurity.isFIPSSupportPKCS12()) {
                this.prf = Mac.getInstance(prfAlgo);
            } else {
                this.prf = Mac.getInstance(prfAlgo, SunJCE.getInstance());
            }
            this.key = deriveKey(prf, passwdBytes, salt, iterCount, keyLength);
        } catch (NoSuchAlgorithmException nsae) {
            // not gonna happen; re-throw just in case
            InvalidKeySpecException ike = new InvalidKeySpecException();
            ike.initCause(nsae);
            throw ike;
        } finally {
            Arrays.fill(passwdBytes, (byte) 0x00);

            // Use the cleaner to zero the key when no longer referenced
            final byte[] k = this.key;
            final char[] p = this.passwd;
            CleanerFactory.cleaner().register(this,
                    () -> {
                        Arrays.fill(k, (byte) 0x00);
                        Arrays.fill(p, '\0');
                    });
        }
    }

    private static byte[] deriveKey(final Mac prf, final byte[] password,
            byte[] salt, int iterCount, int keyLengthInBit) {
        int keyLength = keyLengthInBit/8;
        byte[] key = new byte[keyLength];
        if (RestrictedSecurity.isFIPSSupportPKCS12()) {
            if (!useNativePBES2) {
                new RuntimeException(
                        "The service of loading PKCS12 keystore in FIPS mode is enabled " +
                        "in provider SUN. But the native cypto library for PBE key derive " +
                        "is not loaded. Please check the loading of native cypto library, " +
                        "or remove the service from provider SUN's constraints if loading " +
                        "the PKCS12 keystore is not needed.").printStackTrace();
                System.exit(1);
            }
            String HmacAlgo = prf.getAlgorithm();
            String hashAlgo = HmacAlgo.substring(HmacAlgo.indexOf("Hmac") + 4, HmacAlgo.length());
            boolean hashSupported = true;
            int hashIndex = 0;
            if (hashAlgo.equals("SHA") || hashAlgo.equals("SHA1") || hashAlgo.equals("SHA-1")) {
                hashIndex = NativeCrypto.SHA1_160;
            } else if (hashAlgo.equals("SHA224") || hashAlgo.equals("SHA-224")) {
                hashIndex = NativeCrypto.SHA2_224;
            } else if (hashAlgo.equals("SHA256") || hashAlgo.equals("SHA-256")) {
                hashIndex = NativeCrypto.SHA2_256;
            } else if (hashAlgo.equals("SHA384") || hashAlgo.equals("SHA-384")) {
                hashIndex = NativeCrypto.SHA5_384;
            } else if (hashAlgo.equals("SHA512") || hashAlgo.equals("SHA-512")) {
                hashIndex = NativeCrypto.SHA5_512;
            } else {
                hashSupported = false;
            }
            if (hashSupported) {
                if (nativeCrypto.PBES2Derive(password, password.length, salt, salt.length, iterCount, hashIndex, keyLength, key) != -1) {
                    /*
                     * The return value is 0 indicate that the FIPS mode of operation is not enabled.
                     * Effectively, any non-zero value indicates FIPS mode.
                     */
                    if (nativeCrypto.FIPSMode() != 0) {
                        return key;
                    } else {
                        // System.err.println("FIPS module is not enabled in OpenSSL, please enable. ");
                        new RuntimeException(
                            "Try to invoke a method from a non FIPS compliant OpenSSL. " +
                            "Please enable FIPS module in the configuration  ").printStackTrace();
                        System.exit(1);
                    }
                } else if (nativeCryptTrace) {
                    System.err.println("Native PBE derive failed for algorithm " + hashAlgo + ", using Java implementation.");
                }
            } else if (nativeCryptTrace) {
                System.err.println("The algorithm " + hashAlgo + " is not supported in native code, using Java implementation.");
            }
        }
        try {
            int hlen = prf.getMacLength();
            int intL = (keyLength + hlen - 1)/hlen; // ceiling
            int intR = keyLength - (intL - 1)*hlen; // residue
            byte[] ui = new byte[hlen];
            byte[] ti = new byte[hlen];
            // SecretKeySpec cannot be used, since password can be empty here.
            SecretKey macKey = new SecretKey() {
                private static final long serialVersionUID = 7874493593505141603L;
                @Override
                public String getAlgorithm() {
                    return prf.getAlgorithm();
                }
                @Override
                public String getFormat() {
                    return "RAW";
                }
                @Override
                public byte[] getEncoded() {
                    return password;
                }
                @Override
                public int hashCode() {
                    return Arrays.hashCode(password) * 41 +
                      prf.getAlgorithm().toLowerCase(Locale.ENGLISH).hashCode();
                }
                @Override
                public boolean equals(Object obj) {
                    if (this == obj) return true;
                    if (this.getClass() != obj.getClass()) return false;
                    SecretKey sk = (SecretKey)obj;
                    return prf.getAlgorithm().equalsIgnoreCase(
                        sk.getAlgorithm()) &&
                        MessageDigest.isEqual(password, sk.getEncoded());
                }
            };
            prf.init(macKey);

            byte[] ibytes = new byte[4];
            for (int i = 1; i <= intL; i++) {
                prf.update(salt);
                ibytes[3] = (byte) i;
                ibytes[2] = (byte) ((i >> 8) & 0xff);
                ibytes[1] = (byte) ((i >> 16) & 0xff);
                ibytes[0] = (byte) ((i >> 24) & 0xff);
                prf.update(ibytes);
                prf.doFinal(ui, 0);
                System.arraycopy(ui, 0, ti, 0, ui.length);

                for (int j = 2; j <= iterCount; j++) {
                    prf.update(ui);
                    prf.doFinal(ui, 0);
                    // XOR the intermediate Ui's together.
                    for (int k = 0; k < ui.length; k++) {
                        ti[k] ^= ui[k];
                    }
                }
                if (i == intL) {
                    System.arraycopy(ti, 0, key, (i-1)*hlen, intR);
                } else {
                    System.arraycopy(ti, 0, key, (i-1)*hlen, hlen);
                }
            }
        } catch (GeneralSecurityException gse) {
            throw new RuntimeException("Error deriving PBKDF2 keys", gse);
        }
        return key;
    }

    public byte[] getEncoded() {
        // The key is zeroized by finalize()
        // The reachability fence ensures finalize() isn't called early
        byte[] result = key.clone();
        Reference.reachabilityFence(this);
        return result;
    }

    public String getAlgorithm() {
        return "PBKDF2With" + prf.getAlgorithm();
    }

    public int getIterationCount() {
        return iterCount;
    }

    public char[] getPassword() {
        // The password is zeroized by finalize()
        // The reachability fence ensures finalize() isn't called early
        char[] result = passwd.clone();
        Reference.reachabilityFence(this);
        return result;
    }

    public byte[] getSalt() {
        return salt.clone();
    }

    public String getFormat() {
        return "RAW";
    }

    /**
     * Calculates a hash code value for the object.
     * Objects that are equal will also have the same hashcode.
     */
    public int hashCode() {
        int retval = 0;
        for (int i = 1; i < this.key.length; i++) {
            retval += this.key[i] * i;
        }
        return(retval ^= getAlgorithm().toLowerCase(Locale.ENGLISH).hashCode());
    }

    public boolean equals(Object obj) {
        if (obj == this)
            return true;

        if (!(obj instanceof SecretKey))
            return false;

        SecretKey that = (SecretKey) obj;

        if (!(that.getAlgorithm().equalsIgnoreCase(getAlgorithm())))
            return false;
        if (!(that.getFormat().equalsIgnoreCase("RAW")))
            return false;
        byte[] thatEncoded = that.getEncoded();
        boolean ret = MessageDigest.isEqual(key, thatEncoded);
        Arrays.fill(thatEncoded, (byte)0x00);
        return ret;
    }

    /**
     * Replace the PBE key to be serialized.
     *
     * @return the standard KeyRep object to be serialized
     *
     * @throws ObjectStreamException if a new object representing
     * this PBE key could not be created
     */
    private Object writeReplace() throws ObjectStreamException {
            return new KeyRep(KeyRep.Type.SECRET, getAlgorithm(),
                              getFormat(), getEncoded());
    }
}
