package com.bankguard.sdk

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

class VerifiedCallsReceiver : BroadcastReceiver() {
    companion object {
        private const val TAG = "VerifiedCallsReceiver"
        private const val PREFS_NAME = "bankguard_prefs"
        private const val KEY_CUSTOMER_ID = "customerId"
        private const val KEY_BACKEND_URL = "backendBaseUrl"
        private const val DEFAULT_CUSTOMER_ID = "89012345678"
        private const val DEFAULT_BACKEND_URL = "https://api.doy.codes"
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != "android.intent.action.VERIFIED_FINANCIAL_CALL_QUERY") {
            return
        }

        val incomingNumber = intent.getStringExtra("CALLING_NUMBER")
        if (incomingNumber == null) {
            Log.e(TAG, "No CALLING_NUMBER provided in verified call broadcast")
            return
        }

        val pendingResult = goAsync()
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val customerId = prefs.getString(KEY_CUSTOMER_ID, DEFAULT_CUSTOMER_ID) ?: DEFAULT_CUSTOMER_ID
        val backendBaseUrl = prefs.getString(KEY_BACKEND_URL, DEFAULT_BACKEND_URL) ?: DEFAULT_BACKEND_URL

        Thread {
            try {
                Log.i(TAG, "Querying backend for active call verification for customerId: $customerId, number: $incomingNumber")
                val isVerified = checkBackendForActiveCall(backendBaseUrl, incomingNumber, customerId)
                
                if (!isVerified) {
                    Log.w(TAG, "Spoofed financial call detected: $incomingNumber is not verified!")
                    // Fire the spoof alert to the Flutter layer
                    BankguardPlugin.instance?.invokeMethod(
                        "onSpoofedCallDetected",
                        mapOf(
                            "callerNumber" to incomingNumber,
                            "customerId" to customerId,
                            "reason" to "Spoofed financial call claiming to be bank agent detected"
                        )
                    )
                } else {
                    Log.i(TAG, "Financial call from $incomingNumber verified by backend")
                }

                // Send the verification response broadcast back to the system
                val responseIntent = Intent("android.intent.action.VERIFIED_FINANCIAL_CALL_RESPONSE").apply {
                    putExtra("IS_VERIFIED", isVerified)
                    if (!isVerified) {
                        putExtra("TERMINATE_CALL", true)
                    }
                }
                context.sendBroadcast(responseIntent)
            } catch (e: Exception) {
                Log.e(TAG, "Exception during call verification process", e)
            } finally {
                pendingResult.finish()
            }
        }.start()
    }

    private fun checkBackendForActiveCall(baseUrl: String, incomingNumber: String, customerId: String): Boolean {
        var connection: HttpURLConnection? = null
        return try {
            val cleanUrl = if (baseUrl.endsWith("/")) baseUrl.substring(0, baseUrl.length - 1) else baseUrl
            val encodedCustomerId = URLEncoder.encode(customerId, "UTF-8")
            val encodedNumber = URLEncoder.encode(incomingNumber, "UTF-8")
            
            val url = URL("$cleanUrl/api/calls/active-agents?customer_id=$encodedCustomerId&calling_number=$encodedNumber")
            connection = url.openConnection() as HttpURLConnection
            connection.requestMethod = "GET"
            connection.connectTimeout = 3000
            connection.readTimeout = 3000
            connection.setRequestProperty("Accept", "application/json")

            val responseCode = connection.responseCode
            if (responseCode == 200) {
                val responseText = connection.inputStream.bufferedReader().use { it.readText() }
                // Parse simple JSON: {"active_call": true} or {"active_call": false}
                responseText.contains("\"active_call\":true")
            } else {
                Log.e(TAG, "Backend returned error code: $responseCode")
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Network exception querying call verification service", e)
            false
        } finally {
            connection?.disconnect()
        }
    }
}
