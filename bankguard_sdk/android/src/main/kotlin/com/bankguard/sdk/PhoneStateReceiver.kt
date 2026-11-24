package com.bankguard.sdk

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.telephony.TelephonyManager
import android.util.Log

class PhoneStateReceiver : BroadcastReceiver() {
    companion object {
        private const val TAG = "PhoneStateReceiver"
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != TelephonyManager.ACTION_PHONE_STATE_CHANGED) {
            return
        }

        val state = intent.getStringExtra(TelephonyManager.EXTRA_STATE)
        val incomingNumber = intent.getStringExtra(TelephonyManager.EXTRA_INCOMING_NUMBER) ?: ""
        
        Log.i(TAG, "Phone call state changed: $state, number: $incomingNumber")

        when (state) {
            TelephonyManager.EXTRA_STATE_RINGING -> {
                // Keep ready
            }
            TelephonyManager.EXTRA_STATE_OFFHOOK -> {
                // Active unverified call screening
                val prefs = context.getSharedPreferences("bankguard_prefs", Context.MODE_PRIVATE)
                val customerId = prefs.getString("customerId", "89012345678") ?: "89012345678"
                val backendBaseUrl = prefs.getString("backendBaseUrl", "https://api.doy.codes") ?: "https://api.doy.codes"

                Thread {
                    try {
                        val isVerified = checkBackendForActiveCall(backendBaseUrl, incomingNumber, customerId)
                        if (!isVerified) {
                            Log.w(TAG, "Unverified active call in progress: $incomingNumber")
                            VishingOverlayWindow.show(context, incomingNumber)
                        } else {
                            Log.i(TAG, "Verified outbound call, suppressing overlay: $incomingNumber")
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Error checking backend for call state verification", e)
                        VishingOverlayWindow.show(context, incomingNumber)
                    }
                }.start()
            }
            TelephonyManager.EXTRA_STATE_IDLE -> {
                Log.i(TAG, "Call ended, dismissing vishing overlay")
                VishingOverlayWindow.dismiss()
            }
        }
    }

    private fun checkBackendForActiveCall(baseUrl: String, incomingNumber: String, customerId: String): Boolean {
        if (incomingNumber.isEmpty()) return false
        
        var connection: java.net.HttpURLConnection? = null
        return try {
            val cleanUrl = if (baseUrl.endsWith("/")) baseUrl.substring(0, baseUrl.length - 1) else baseUrl
            val encodedCustomerId = java.net.URLEncoder.encode(customerId, "UTF-8")
            val encodedNumber = java.net.URLEncoder.encode(incomingNumber, "UTF-8")
            
            val url = java.net.URL("$cleanUrl/api/calls/active-agents?customer_id=$encodedCustomerId&calling_number=$encodedNumber")
            connection = url.openConnection() as java.net.HttpURLConnection
            connection.requestMethod = "GET"
            connection.connectTimeout = 2000
            connection.readTimeout = 2000
            connection.setRequestProperty("Accept", "application/json")

            val responseCode = connection.responseCode
            if (responseCode == 200) {
                val responseText = connection.inputStream.bufferedReader().use { it.readText() }
                responseText.contains("\"active_call\":true")
            } else {
                false
            }
        } catch (e: Exception) {
            false
        } finally {
            connection?.disconnect()
        }
    }
}
