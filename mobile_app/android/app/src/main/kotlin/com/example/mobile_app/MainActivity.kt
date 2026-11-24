package com.example.mobile_app

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import com.google.android.gms.auth.api.phone.SmsRetriever
import com.google.android.gms.auth.api.phone.SmsRetrieverClient
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
	private val methodChannelName = "trustyono_share"
	private val eventChannelName = "trustyono_share_stream"
	private val smsMethodChannelName = "trustyono_sms"
	private val smsEventChannelName = "trustyono_sms_stream"
	private val smsConsentRequest = 9091
	private var latestSharedText: String? = null
	private var eventSink: EventChannel.EventSink? = null
	private var smsEventSink: EventChannel.EventSink? = null
	private var smsClient: SmsRetrieverClient? = null

	override fun onCreate(savedInstanceState: Bundle?) {
		super.onCreate(savedInstanceState)
		handleShareIntent(intent)
		if (Build.VERSION.SDK_INT >= 33) {
			registerReceiver(
				smsReceiver,
				IntentFilter(SmsRetriever.SMS_RETRIEVED_ACTION),
				Context.RECEIVER_NOT_EXPORTED
			)
		} else {
			registerReceiver(smsReceiver, IntentFilter(SmsRetriever.SMS_RETRIEVED_ACTION))
		}
		smsClient = SmsRetriever.getClient(this)
	}

	override fun onNewIntent(intent: Intent) {
		super.onNewIntent(intent)
		handleShareIntent(intent)
	}

	override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
		super.configureFlutterEngine(flutterEngine)

		// Share intent channel (app-specific)
		MethodChannel(flutterEngine.dartExecutor.binaryMessenger, methodChannelName)
			.setMethodCallHandler { call, result ->
				when (call.method) {
					"getSharedText" -> {
						result.success(latestSharedText)
						latestSharedText = null
					}
					else -> result.notImplemented()
				}
			}

		// SMS user consent channel (app-specific)
		MethodChannel(flutterEngine.dartExecutor.binaryMessenger, smsMethodChannelName)
			.setMethodCallHandler { call, result ->
				when (call.method) {
					"startSmsUserConsent" -> {
						smsClient?.startSmsUserConsent(null)
						result.success(true)
					}
					else -> result.notImplemented()
				}
			}

		// Share stream (app-specific)
		EventChannel(flutterEngine.dartExecutor.binaryMessenger, eventChannelName)
			.setStreamHandler(object : EventChannel.StreamHandler {
				override fun onListen(arguments: Any?, sink: EventChannel.EventSink) {
					eventSink = sink
				}
				override fun onCancel(arguments: Any?) {
					eventSink = null
				}
			})

		// SMS stream (app-specific)
		EventChannel(flutterEngine.dartExecutor.binaryMessenger, smsEventChannelName)
			.setStreamHandler(object : EventChannel.StreamHandler {
				override fun onListen(arguments: Any?, sink: EventChannel.EventSink) {
					smsEventSink = sink
				}
				override fun onCancel(arguments: Any?) {
					smsEventSink = null
				}
			})

		// NOTE: Notification and Call streams are now handled by the TrustYONO SDK plugin.
		// No manual EventChannel wiring needed here.
	}

	override fun onDestroy() {
		unregisterReceiver(smsReceiver)
		super.onDestroy()
	}

	override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
		super.onActivityResult(requestCode, resultCode, data)
		if (requestCode == smsConsentRequest && resultCode == Activity.RESULT_OK && data != null) {
			val message = data.getStringExtra(SmsRetriever.EXTRA_SMS_MESSAGE)
			if (!message.isNullOrBlank()) {
				smsEventSink?.success(message)
			}
		}
	}

	private fun handleShareIntent(intent: Intent?) {
		if (intent == null) return
		if (Intent.ACTION_SEND == intent.action && intent.type == "text/plain") {
			val sharedText = intent.getStringExtra(Intent.EXTRA_TEXT)
			if (!sharedText.isNullOrBlank()) {
				latestSharedText = sharedText
				eventSink?.success(sharedText)
			}
		}
	}

	private val smsReceiver = object : BroadcastReceiver() {
		override fun onReceive(context: Context?, intent: Intent?) {
			if (intent == null || intent.action != SmsRetriever.SMS_RETRIEVED_ACTION) return
			val extras = intent.extras ?: return
			val status = extras.get(SmsRetriever.EXTRA_STATUS)
			if (status is com.google.android.gms.common.api.Status) {
				if (status.statusCode == com.google.android.gms.common.api.CommonStatusCodes.SUCCESS) {
					val consentIntent = extras.getParcelable<Intent>(SmsRetriever.EXTRA_CONSENT_INTENT)
					if (consentIntent != null) {
						startActivityForResult(consentIntent, smsConsentRequest)
					}
				}
			}
		}
	}
}
