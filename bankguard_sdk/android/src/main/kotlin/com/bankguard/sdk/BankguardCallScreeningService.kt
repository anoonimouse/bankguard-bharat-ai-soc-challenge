package com.bankguard.sdk

import android.content.Intent
import android.telecom.CallScreeningService
import android.telecom.Call.Details

/**
 * SDK-level Call Screening Service.
 * Intercepts incoming calls and broadcasts the number to the host app
 * using a dynamic action string based on the host's package name.
 */
class BankguardCallScreeningService : CallScreeningService() {

    private fun getBroadcastAction(): String {
        return "$packageName.BANKGUARD_CALL"
    }

    override fun onScreenCall(details: Details) {
        val number = details.handle?.schemeSpecificPart ?: ""
        val intent = Intent(getBroadcastAction())
        intent.putExtra("number", number)
        intent.putExtra("incoming", details.callDirection == Details.DIRECTION_INCOMING)
        sendBroadcast(intent)

        val response = CallResponse.Builder().build()
        respondToCall(details, response)
    }
}
