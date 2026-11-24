package com.bankguard.sdk

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature

/**
 * Task 5: Hardware-bound ECDSA key generation using Android Keystore TEE/StrongBox.
 *
 * The private key is generated inside the device's Trusted Execution Environment
 * (or StrongBox secure element on Pixel 3+ and Samsung S10+). It physically cannot
 * be exported, even with root access. This prevents:
 *
 *   - Digital Lutera attack: attacker steals SMS token, registers on another device.
 *     With TEE binding, the backend challenges the device to sign a nonce.
 *     The attacker's device cannot produce a valid signature because it doesn't
 *     have the original device's private key.
 *
 *   - SIM swap attack: even after porting the phone number, the attacker's device
 *     doesn't have the hardware key from the victim's phone.
 *
 * Usage:
 *   1. Call generateDeviceKey() during UPI registration / device binding
 *   2. Export the public key with getPublicKeyBase64() and send to backend
 *   3. Backend issues a challenge nonce for each sensitive transaction
 *   4. Client signs the nonce with signChallenge(nonce)
 *   5. Backend verifies signature against stored public key
 *
 * If signature doesn't match -> request is from a different device -> reject
 */
object HardwareKeyManager {

    private const val TAG = "HW_KEY_MANAGER"
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val KEY_ALIAS = "bankguard_device_bind_key"
    private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

    /**
     * Generate a non-exportable ECDSA P-256 key pair in TEE/StrongBox.
     *
     * The key is:
     *   - Bound to this physical device's secure hardware
     *   - Non-exportable (private key never leaves the TEE)
     *   - Persistent across app updates (but not factory resets)
     *   - Requires no user interaction (no biometric gate by default)
     *
     * Returns true if key generation succeeded.
     * Returns false if TEE is not available (very old devices, emulators).
     *
     * Idempotent: if the key already exists, returns true without regenerating.
     */
    @JvmStatic
    fun generateDeviceKey(): Boolean {
        // Check if key already exists
        if (hasDeviceKey()) {
            Log.i(TAG, "Device key already exists, skipping generation")
            return true
        }

        return try {
            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                KEYSTORE_PROVIDER
            )

            val specBuilder = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                // User authentication not required for transaction signing
                // (the UPI flow already requires PIN/biometric at the app level)
                .setUserAuthenticationRequired(false)

            // Prefer StrongBox if available (Pixel 3+, Samsung S10+, etc.)
            // StrongBox is a discrete tamper-resistant hardware chip
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                try {
                    specBuilder.setIsStrongBoxBacked(true)
                    keyPairGenerator.initialize(specBuilder.build())
                    keyPairGenerator.generateKeyPair()
                    Log.i(TAG, "Device key generated in StrongBox secure element")
                    return true
                } catch (e: Exception) {
                    // StrongBox not available, fall back to TEE
                    Log.w(TAG, "StrongBox not available, falling back to TEE: ${e.message}")
                    specBuilder.setIsStrongBoxBacked(false)
                }
            }

            // TEE fallback (available on virtually all ARM devices since 2014)
            keyPairGenerator.initialize(specBuilder.build())
            keyPairGenerator.generateKeyPair()
            Log.i(TAG, "Device key generated in TEE")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Device key generation failed: ${e.message}", e)
            false
        }
    }

    /**
     * Check if the device binding key exists in the Keystore.
     */
    @JvmStatic
    fun hasDeviceKey(): Boolean {
        return try {
            val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
            keyStore.load(null)
            keyStore.containsAlias(KEY_ALIAS)
        } catch (e: Exception) {
            Log.e(TAG, "Keystore check failed: ${e.message}")
            false
        }
    }

    /**
     * Export the public key as a Base64 string.
     *
     * This is safe to send to the backend -- only the public key is exported.
     * The private key never leaves the TEE/StrongBox.
     *
     * Returns null if no key exists or export fails.
     */
    @JvmStatic
    fun getPublicKeyBase64(): String? {
        return try {
            val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
            keyStore.load(null)

            val entry = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
                ?: return null

            val publicKeyBytes = entry.certificate.publicKey.encoded
            Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "Public key export failed: ${e.message}")
            null
        }
    }

    /**
     * Sign a challenge nonce with the device-bound private key.
     *
     * The nonce is typically a random string issued by the backend for each
     * sensitive transaction (UPI transfer, beneficiary add, etc.)
     *
     * Returns the Base64-encoded ECDSA signature, or null on failure.
     */
    @JvmStatic
    fun signChallenge(challengeBytes: ByteArray): String? {
        return try {
            val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
            keyStore.load(null)

            val entry = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
                ?: run {
                    Log.e(TAG, "No device key found for signing")
                    return null
                }

            val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
            signature.initSign(entry.privateKey)
            signature.update(challengeBytes)

            val signedBytes = signature.sign()
            Base64.encodeToString(signedBytes, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "Challenge signing failed: ${e.message}", e)
            null
        }
    }

    /**
     * Verify a signature locally (for testing / self-attestation).
     * In production, verification happens on the backend.
     */
    @JvmStatic
    fun verifySignature(challengeBytes: ByteArray, signatureBase64: String): Boolean {
        return try {
            val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
            keyStore.load(null)

            val entry = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
                ?: return false

            val signatureBytes = Base64.decode(signatureBase64, Base64.NO_WRAP)
            val verifier = Signature.getInstance(SIGNATURE_ALGORITHM)
            verifier.initVerify(entry.certificate)
            verifier.update(challengeBytes)
            verifier.verify(signatureBytes)
        } catch (e: Exception) {
            Log.e(TAG, "Signature verification failed: ${e.message}")
            false
        }
    }

    /**
     * Delete the device binding key. Use only during device unbinding / account reset.
     * After deletion, generateDeviceKey() must be called again to re-register.
     */
    @JvmStatic
    fun deleteDeviceKey(): Boolean {
        return try {
            val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
            keyStore.load(null)
            keyStore.deleteEntry(KEY_ALIAS)
            Log.i(TAG, "Device key deleted")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Device key deletion failed: ${e.message}")
            false
        }
    }

    /**
     * Get key metadata for telemetry / diagnostics.
     * Returns a map suitable for MethodChannel transmission.
     */
    @JvmStatic
    fun getKeyInfo(): HashMap<String, Any> {
        val info = hashMapOf<String, Any>(
            "exists" to hasDeviceKey(),
            "alias" to KEY_ALIAS,
            "algorithm" to "EC/P-256",
            "signatureAlgorithm" to SIGNATURE_ALGORITHM
        )

        val pubKey = getPublicKeyBase64()
        if (pubKey != null) {
            info["publicKey"] = pubKey
        }

        return info
    }
}
