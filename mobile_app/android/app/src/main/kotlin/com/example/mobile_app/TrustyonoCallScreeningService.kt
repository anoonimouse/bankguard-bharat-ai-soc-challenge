package com.example.mobile_app

import android.content.Intent
import android.telecom.CallScreeningService
import android.telecom.Call.Details

class TrustyonoCallScreeningService : CallScreeningService() {
    private val callAction = "com.example.mobile_app.TRUSTYONO_CALL"

    override fun onScreenCall(details: Details) {
        val number = details.handle?.schemeSpecificPart ?: ""
        val intent = Intent(callAction)
        intent.putExtra("number", number)
        intent.putExtra("incoming", details.callDirection == Details.DIRECTION_INCOMING)
        sendBroadcast(intent)

        val response = CallResponse.Builder().build()
        respondToCall(details, response)
    }
}
