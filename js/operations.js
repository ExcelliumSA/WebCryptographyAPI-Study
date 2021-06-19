/**
 * Contains only crypto operations representing each demo of the lab.
 */

//See https://developer.mozilla.org/en-US/docs/Web/API/Window/crypto
const CRYPTO_OBJ = window.crypto;

//See https://developer.mozilla.org/en-US/docs/Web/API/TextEncoder
const TEXT_ENCODER = new TextEncoder("utf8");

//See https://developer.mozilla.org/en-US/docs/Web/API/TextDecoder
const TEXT_DECODER = new TextDecoder("utf8");

//Credits: https://stackoverflow.com/a/40031979/451455
function toHex(buffer) {
    return [...new Uint8Array(buffer)].map(x => x.toString(16).padStart(2, "0")).join("");
}

function performRandomValuesGeneration(wantedLength) {
    if (wantedLength > 10000) {
        //See https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues#exceptions
        return "LENGTH_UNSUPPORTED";
    }
    let buffer = new Int32Array(wantedLength);
    CRYPTO_OBJ.getRandomValues(buffer);
    return toHex(buffer);
}

async function performSha512Hash(sourceData) {
    let dataEncoded = TEXT_ENCODER.encode(sourceData);
    let hashBytes = await CRYPTO_OBJ.subtle.digest("SHA-512", dataEncoded);
    return toHex(hashBytes);
}

async function performSymmetricKeyGenerationForEncryptionDecryptionUsageWithAESGCM() {
    //Generate a 256 bits key for AES-GCM symmetric encryption algorithm
    //See https://developer.mozilla.org/en-US/docs/Web/API/AesKeyGenParams
    let aesKeyGenParams = {
        name: "AES-GCM",
        length: 256
    };
    let keyUsages = ["encrypt", "decrypt"];
    //See https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey
    let cryptoKey = await CRYPTO_OBJ.subtle.generateKey(aesKeyGenParams, true, keyUsages);
    return cryptoKey;
}

async function performEncryptionDecryptionWithAESGCM(sourceData, cryptoKey) {
    let nonce = new Int32Array(12); //96 bits
    CRYPTO_OBJ.getRandomValues(nonce);
    //See https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams
    let additData = new Int32Array(16); //128 bits
    CRYPTO_OBJ.getRandomValues(additData);
    let aesGcmParams = {
        name: "AES-GCM",
        iv: nonce,
        additionalData: additData,
        tagLength: 128 //16 bytes
    };
    let dataEncoded = TEXT_ENCODER.encode(sourceData);
    //See https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt
    let encryptedData = await CRYPTO_OBJ.subtle.encrypt(aesGcmParams, cryptoKey, dataEncoded)
    //See https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/decrypt
    let decryptedData = await CRYPTO_OBJ.subtle.decrypt(aesGcmParams, cryptoKey, encryptedData)
    let plainText = TEXT_DECODER.decode(decryptedData);
    let result = {
        encryptedData: toHex(encryptedData),
        cycleSucceed: (sourceData === plainText)
    }
    return result;
}

async function performSecretGenerationForSignVerifyUsageWithHMAC() {
    //Generate a secret (cryptoKey) for HMAC operation with SHA-512
    //See https://developer.mozilla.org/en-US/docs/Web/API/HmacKeyGenParams
    let hmacKeyGenParams = {
        name: "HMAC",
        hash: "SHA-512"
    };
    let keyUsages = ["sign", "verify"];
    //See https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey
    let cryptoKey = await CRYPTO_OBJ.subtle.generateKey(hmacKeyGenParams, true, keyUsages);
    return cryptoKey;
}

async function performSignVerifyWithHMAC(sourceData, cryptoKey) {
    let algorithm = "HMAC";
    let dataEncoded = TEXT_ENCODER.encode(sourceData);
    //See https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/sign
    let signature = await CRYPTO_OBJ.subtle.sign(algorithm, cryptoKey, dataEncoded);
    //See https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/verify
    let isValid = await CRYPTO_OBJ.subtle.verify(algorithm, cryptoKey, signature, dataEncoded);
    let result = {
        signature: toHex(signature),
        cycleSucceed: isValid
    }
    return result;
}

async function performAsymmetricKeyGenerationForEncryptionDecryptionUsageWithRSAOAEP() {
    //RSA was chosen because EC was not supported by the "algorithm" parameter at the time of the POC (June 2021):
    //See https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt#parameters
    //Generate a RSA-OAEP key pair with a size of 4096 bits
    //See https://developer.mozilla.org/en-US/docs/Web/API/RsaHashedKeyGenParams
    //See https://www.keylength.com/en/3/
    //See https://developer.mozilla.org/en-US/docs/Web/API/RsaHashedKeyGenParams#properties
    let rsaHashedKeyGenParams = {
        name: "RSA-OAEP",
        modulusLength: 4096,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-512"
    };
    let keyUsages = ["encrypt", "decrypt"];
    //See https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey
    let cryptoKeyPair = await CRYPTO_OBJ.subtle.generateKey(rsaHashedKeyGenParams, true, keyUsages);
    return cryptoKeyPair;
}

async function performEncryptionDecryptionWithRSAOAEP(sourceData, cryptoKeyPairPublicKey, cryptoKeyPairPrivateKey) {
    let labelData = new Int32Array(32); //256 bits
    CRYPTO_OBJ.getRandomValues(labelData);
    //See https://developer.mozilla.org/en-US/docs/Web/API/RsaOaepParams    
    let rsaOaepParams = {
        name: "RSA-OAEP",
        label: labelData
    };
    let dataEncoded = TEXT_ENCODER.encode(sourceData);
    //See https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt
    let encryptedData = await CRYPTO_OBJ.subtle.encrypt(rsaOaepParams, cryptoKeyPairPublicKey, dataEncoded)
    //See https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/decrypt
    let decryptedData = await CRYPTO_OBJ.subtle.decrypt(rsaOaepParams, cryptoKeyPairPrivateKey, encryptedData)
    let plainText = TEXT_DECODER.decode(decryptedData);
    let result = {
        encryptedData: toHex(encryptedData),
        cycleSucceed: (sourceData === plainText)
    }
    return result;
}

function performIdentificationOfContentLengthLimitForEncryptionWithRSAOAEP(cryptoKeyPairPublicKey) {
    let labelData = new Int32Array(32);
    CRYPTO_OBJ.getRandomValues(labelData);  
    let rsaOaepParams = {
        name: "RSA-OAEP",
        label: labelData
    };  
    let dataEncoded = null;  
    for (let i = 100; i < 1000000; i++) {
        console.debug("Test with value of length " + i + "...");
        dataEncoded = TEXT_ENCODER.encode("T".repeat(i));
        CRYPTO_OBJ.subtle.encrypt(rsaOaepParams, cryptoKeyPairPublicKey, dataEncoded).catch(err => {
            console.warn(err);
            return i;
        });
    }
}