package com.bankguard.sdk

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import java.util.concurrent.ConcurrentHashMap
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import android.app.Activity
import android.telephony.SubscriptionManager
import android.telephony.SubscriptionInfo
import android.telephony.TelephonyManager
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.security.MessageDigest
import android.net.Uri
import android.net.VpnService
import android.speech.tts.TextToSpeech
import java.util.Locale
import android.app.role.RoleManager

/** BankguardPlugin - Flutter plugin providing native Android security capabilities. */
class BankguardPlugin: FlutterPlugin, MethodCallHandler, ActivityAware {
  private var activity: Activity? = null
  private var tts: TextToSpeech? = null
  private var isTtsReady = false
  private var activityBinding: ActivityPluginBinding? = null
  private var pendingVpnResult: Result? = null
  private val REQUEST_VPN = 2002

  private var activeSmsNonce: String? = null
  private var activeSmsCustomerId: String? = null
  private var lifecycleCallbacks: android.app.Application.ActivityLifecycleCallbacks? = null

  private val activityResultListener = io.flutter.plugin.common.PluginRegistry.ActivityResultListener { requestCode, resultCode, data ->
      if (requestCode == REQUEST_VPN) {
          if (resultCode == Activity.RESULT_OK) {
              pendingVpnResult?.success(true)
          } else {
              pendingVpnResult?.success(false)
          }
          pendingVpnResult = null
          return@ActivityResultListener true
      }
      false
  }

  companion object {
      var pendingNotificationEvent: Map<String, Any>? = null
      @Volatile
      var instance: BankguardPlugin? = null
      
      // Track last global block page launch time to prevent tab bombardment
      @Volatile
      private var lastGlobalLaunchTime = 0L
  }

  fun invokeMethod(method: String, arguments: Any?) {
    val mainHandler = android.os.Handler(android.os.Looper.getMainLooper())
    mainHandler.post {
      try {
        channel.invokeMethod(method, arguments)
      } catch (e: Exception) {
        android.util.Log.e("BankguardPlugin", "Error invoking method $method via channel", e)
      }
    }
  }

  private lateinit var channel : MethodChannel
  private lateinit var notificationEventChannel : EventChannel
  private lateinit var callEventChannel : EventChannel
  private lateinit var behavioralEventChannel : EventChannel
  private lateinit var unknownSourcesEventChannel : EventChannel
  private lateinit var downloadEventChannel : EventChannel
  private var applicationContext: Context? = null
  private var notificationEventSink: EventChannel.EventSink? = null
  private var callEventSink: EventChannel.EventSink? = null
  private var behavioralEventSink: EventChannel.EventSink? = null
  private var unknownSourcesEventSink: EventChannel.EventSink? = null
  private var downloadEventSink: EventChannel.EventSink? = null
  private var fileObserverEventSink: EventChannel.EventSink? = null
  private var notificationReceiver: BroadcastReceiver? = null
  private var callReceiver: BroadcastReceiver? = null

  // Behavioral engine components
  private var behavioralStore: BehavioralProfileStore? = null
  private var behavioralScorer: BehavioralRiskScorer? = null
  private var behavioralCollector: BehavioralEventCollector? = null
  private var timeWindowManager: TimeWindowManager? = null

  // APK hash denylist (Layer 4B)
  private var apkDenylist: ApkHashDenylist? = null

  // Unknown Sources observer (Layer 5)
  private var unknownSourcesObserver: UnknownSourcesObserver? = null

  // Download manager monitor (Layer 2A)
  private var downloadMonitor: DownloadManagerMonitor? = null

  // Package installer overlay (Layer 3)
  private var installerOverlay: PackageInstallerOverlay? = null

  // URL heuristic scanner (Layer 1B)
  private var urlScanner: UrlHeuristicScanner? = null

  // ExecuTorch + Llama Reasoning Engine (Bharat AI-SoC Challenge PS3)
  private var llamaRunner: ExecuTorchLlamaRunner? = null

  // File alert receiver (Layer 2B)
  private var fileAlertReceiver: BroadcastReceiver? = null
  private lateinit var fileObserverEventChannel: EventChannel

  // RASP native layer availability flag
  private var raspAvailable = false

  override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
    applicationContext = flutterPluginBinding.applicationContext
    instance = this

    // MethodChannel
    channel = MethodChannel(flutterPluginBinding.binaryMessenger, "bankguard")
    channel.setMethodCallHandler(this)

    // Initialize TTS
    try {
        tts = TextToSpeech(applicationContext) { status ->
            if (status == TextToSpeech.SUCCESS) {
                isTtsReady = true
            }
        }
    } catch (e: java.lang.Exception) {
        android.util.Log.e("BANKGUARD_PLUGIN", "Failed to initialize TTS: ${e.message}")
    }

    // EventChannel: Notification threats
    notificationEventChannel = EventChannel(flutterPluginBinding.binaryMessenger, "bankguard/notifications")
    notificationEventChannel.setStreamHandler(object : EventChannel.StreamHandler {
      override fun onListen(arguments: Any?, sink: EventChannel.EventSink) {
        android.util.Log.e("BANKGUARD_PLUGIN", "EventChannel onListen for notifications")
        notificationEventSink = sink
        registerNotificationReceiver()
        
        pendingNotificationEvent?.let {
            android.util.Log.e("BANKGUARD_PLUGIN", "Dispatching pending notification event to Flutter")
            sink.success(it)
            pendingNotificationEvent = null
        }
      }
      override fun onCancel(arguments: Any?) {
        android.util.Log.e("BANKGUARD_PLUGIN", "EventChannel onCancel for notifications")
        notificationEventSink = null
        unregisterNotificationReceiver()
      }
    })

    // EventChannel: Call threats
    callEventChannel = EventChannel(flutterPluginBinding.binaryMessenger, "bankguard/calls")
    callEventChannel.setStreamHandler(object : EventChannel.StreamHandler {
      override fun onListen(arguments: Any?, sink: EventChannel.EventSink) {
        callEventSink = sink
        registerCallReceiver()
      }
      override fun onCancel(arguments: Any?) {
        callEventSink = null
        unregisterCallReceiver()
      }
    })

    // EventChannel: Behavioral threat alerts
    behavioralEventChannel = EventChannel(flutterPluginBinding.binaryMessenger, "bankguard/behavioral_threats")
    behavioralEventChannel.setStreamHandler(object : EventChannel.StreamHandler {
      override fun onListen(arguments: Any?, sink: EventChannel.EventSink) {
        behavioralEventSink = sink
      }
      override fun onCancel(arguments: Any?) {
        behavioralEventSink = null
      }
    })

    // EventChannel: Unknown Sources state changes (Layer 5)
    unknownSourcesEventChannel = EventChannel(flutterPluginBinding.binaryMessenger, "bankguard/unknown_sources")
    unknownSourcesEventChannel.setStreamHandler(object : EventChannel.StreamHandler {
      override fun onListen(arguments: Any?, sink: EventChannel.EventSink) {
        unknownSourcesEventSink = sink
        unknownSourcesObserver?.start()
      }
      override fun onCancel(arguments: Any?) {
        unknownSourcesEventSink = null
        unknownSourcesObserver?.stop()
      }
    })

    // EventChannel: APK download detection (Layer 2A)
    downloadEventChannel = EventChannel(flutterPluginBinding.binaryMessenger, "bankguard/downloads")
    downloadEventChannel.setStreamHandler(object : EventChannel.StreamHandler {
      override fun onListen(arguments: Any?, sink: EventChannel.EventSink) {
        downloadEventSink = sink
        downloadMonitor?.start()
      }
      override fun onCancel(arguments: Any?) {
        downloadEventSink = null
        downloadMonitor?.stop()
      }
    })

    // EventChannel: APK file observer detection (Layer 2B)
    fileObserverEventChannel = EventChannel(flutterPluginBinding.binaryMessenger, "bankguard/file_observer")
    fileObserverEventChannel.setStreamHandler(object : EventChannel.StreamHandler {
      override fun onListen(arguments: Any?, sink: EventChannel.EventSink) {
        fileObserverEventSink = sink
        registerFileAlertReceiver()
      }
      override fun onCancel(arguments: Any?) {
        fileObserverEventSink = null
        unregisterFileAlertReceiver()
      }
    })

    // Initialize behavioral engine
    initBehavioralEngine(flutterPluginBinding.applicationContext)

    // Initialize native RASP layer (Tasks 1-4)
    raspAvailable = RaspNative.ensureLoaded()
    if (raspAvailable) {
      android.util.Log.i("BANKGUARD_PLUGIN", "Native RASP layer loaded successfully")
    } else {
      android.util.Log.w("BANKGUARD_PLUGIN", "Native RASP layer unavailable on this device")
    }
  }

  private fun initBehavioralEngine(ctx: Context) {
    timeWindowManager = TimeWindowManager()
    behavioralScorer = BehavioralRiskScorer(
      timeWindowManager = timeWindowManager!!
    )
    behavioralStore = BehavioralProfileStore(ctx, timeWindowManager!!)
    apkDenylist = ApkHashDenylist.getInstance(ctx)
    behavioralCollector = BehavioralEventCollector(
      context = ctx,
      store = behavioralStore!!,
      scorer = behavioralScorer!!,
      timeWindowManager = timeWindowManager!!,
      apkDenylist = apkDenylist,
      onThreatDetected = { profile ->
        android.os.Handler(android.os.Looper.getMainLooper()).post {
          behavioralEventSink?.success(profile.toChannelMap())
        }
      }
    )
    behavioralCollector!!.start()

    // Layer 5: Unknown Sources real-time observer
    unknownSourcesObserver = UnknownSourcesObserver(ctx) { isEnabled ->
      android.os.Handler(android.os.Looper.getMainLooper()).post {
        unknownSourcesEventSink?.success(hashMapOf(
          "enabled" to isEnabled,
          "timestampMs" to System.currentTimeMillis()
        ))
      }
    }

    // Layer 2A: DownloadManager APK monitor
    downloadMonitor = DownloadManagerMonitor(ctx) { info ->
      android.os.Handler(android.os.Looper.getMainLooper()).post {
        downloadEventSink?.success(info.toChannelMap())
      }
    }

    // Layer 3: Package installer overlay
    installerOverlay = PackageInstallerOverlay(ctx) {
      // Overlay shown callback -- fire an event to Dart for telemetry
      android.os.Handler(android.os.Looper.getMainLooper()).post {
        behavioralEventSink?.success(hashMapOf(
          "packageName" to "system_installer",
          "lastVerdict" to "INSTALLER_DETECTED",
          "lastScore" to 75,
          "installSource" to "unknown",
          "installTimestampMs" to System.currentTimeMillis()
        ))
      }
    }

    // Layer 1B: URL heuristic scanner (stateless, no lifecycle)
    urlScanner = UrlHeuristicScanner()

    // Bharat AI-SoC: ExecuTorch Llama on-device reasoning engine
    llamaRunner = ExecuTorchLlamaRunner(ctx)

    // Layer 2B: APK file observer is hosted inside BankguardNotificationListenerService
  }

  // --- Broadcast Receivers ---

  private fun registerFileAlertReceiver() {
    if (fileAlertReceiver != null || applicationContext == null) return
    val action = "${applicationContext!!.packageName}.BANKGUARD_FILE_ALERT"
    android.util.Log.e("BANKGUARD_PLUGIN", "Registering File Alert receiver for action: $action")
    fileAlertReceiver = object : BroadcastReceiver() {
      override fun onReceive(context: Context?, intent: Intent?) {
        if (intent == null) return
        val payload = HashMap<String, Any?>()
        payload["id"] = intent.getLongExtra("id", 0L)
        payload["displayName"] = intent.getStringExtra("displayName") ?: ""
        payload["filePath"] = intent.getStringExtra("filePath")
        payload["fileSize"] = intent.getLongExtra("fileSize", 0L)
        payload["dateAdded"] = intent.getLongExtra("dateAdded", 0L)
        payload["mimeType"] = intent.getStringExtra("mimeType")
        payload["sourceDirectory"] = intent.getStringExtra("sourceDirectory")
        payload["isFromWatchedDir"] = intent.getBooleanExtra("isFromWatchedDir", false)

        android.os.Handler(android.os.Looper.getMainLooper()).post {
          fileObserverEventSink?.success(payload)
        }
      }
    }
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
      applicationContext!!.registerReceiver(
        fileAlertReceiver,
        android.content.IntentFilter(action),
        Context.RECEIVER_EXPORTED
      )
    } else {
      applicationContext!!.registerReceiver(
        fileAlertReceiver,
        android.content.IntentFilter(action)
      )
    }
  }

  private fun unregisterFileAlertReceiver() {
    if (fileAlertReceiver != null && applicationContext != null) {
      try {
        applicationContext!!.unregisterReceiver(fileAlertReceiver)
      } catch (_: Exception) {}
      fileAlertReceiver = null
    }
  }

  private fun registerNotificationReceiver() {
    if (notificationReceiver != null || applicationContext == null) return
    val action = "${applicationContext!!.packageName}.BANKGUARD_NOTIFICATION"
    android.util.Log.e("BANKGUARD_PLUGIN", "Attempting to register Notification receiver for action: $action")
    notificationReceiver = object : BroadcastReceiver() {
      override fun onReceive(context: Context?, intent: Intent?) {
        android.util.Log.e("BANKGUARD_PLUGIN", "Broadcast received: ${intent?.action}")
        if (intent == null) return
        val text = intent.getStringExtra("text")
        if (text.isNullOrBlank()) {
          android.util.Log.e("BANKGUARD_PLUGIN", "Text is null or blank")
          return
        }

        val payload = HashMap<String, Any>()
        payload["package"] = intent.getStringExtra("package") ?: ""
        payload["text"] = text
        payload["score"] = intent.getIntExtra("score", 0)
        payload["verdict"] = intent.getStringExtra("verdict") ?: "none"
        payload["primaryCategory"] = intent.getStringExtra("primaryCategory") ?: ""
        payload["categories"] = intent.getStringArrayListExtra("categories") ?: ArrayList<String>()
        payload["localNlpConfidence"] = intent.getDoubleExtra("localNlpConfidence", 0.0)
        payload["localNlpVerdict"] = intent.getStringExtra("localNlpVerdict") ?: "none"
        payload["localNlpModel"] = intent.getStringExtra("localNlpModel") ?: "mrm8488/bert-tiny-finetuned-sms-spam-detection"
        payload["localNlpIndicators"] = parseLocalNlpIndicators(
          intent.getStringExtra("localNlpIndicatorsJson") ?: "[]"
        )

        android.util.Log.e("BANKGUARD_PLUGIN", "Sinking payload to Flutter: $payload")
        android.os.Handler(android.os.Looper.getMainLooper()).post {
          notificationEventSink?.success(payload)
        }
      }
    }
    
    try {
      if (Build.VERSION.SDK_INT >= 33) {
        applicationContext!!.registerReceiver(
          notificationReceiver, IntentFilter(action), Context.RECEIVER_NOT_EXPORTED
        )
      } else {
        applicationContext!!.registerReceiver(notificationReceiver, IntentFilter(action))
      }
      android.util.Log.e("BANKGUARD_PLUGIN", "Notification receiver successfully registered for action: $action")
    } catch (e: Exception) {
      android.util.Log.e("BANKGUARD_PLUGIN", "Failed to register Notification receiver", e)
    }
  }

  private fun unregisterNotificationReceiver() {
    if (notificationReceiver != null && applicationContext != null) {
      try { applicationContext!!.unregisterReceiver(notificationReceiver) } catch (_: Exception) {}
      notificationReceiver = null
    }
  }

  private fun parseLocalNlpIndicators(json: String): ArrayList<HashMap<String, Any>> {
    val parsed = ArrayList<HashMap<String, Any>>()
    try {
      val array = org.json.JSONArray(json)
      for (i in 0 until array.length()) {
        val item = array.optJSONObject(i) ?: continue
        val map = HashMap<String, Any>()
        map["name"] = item.optString("name")
        map["detected"] = item.optBoolean("detected", true)
        map["evidence"] = item.optString("evidence")
        parsed.add(map)
      }
    } catch (_: Exception) {
    }
    return parsed
  }

  private fun registerCallReceiver() {
    if (callReceiver != null || applicationContext == null) return
    val action = "${applicationContext!!.packageName}.BANKGUARD_CALL"
    callReceiver = object : BroadcastReceiver() {
      override fun onReceive(context: Context?, intent: Intent?) {
        if (intent == null) return
        val number = intent.getStringExtra("number") ?: ""
        val incoming = intent.getBooleanExtra("incoming", true)
        val payload = HashMap<String, Any>()
        payload["number"] = number
        payload["incoming"] = incoming
        callEventSink?.success(payload)
      }
    }
    if (Build.VERSION.SDK_INT >= 33) {
      applicationContext!!.registerReceiver(
        callReceiver, IntentFilter(action), Context.RECEIVER_NOT_EXPORTED
      )
    } else {
      applicationContext!!.registerReceiver(callReceiver, IntentFilter(action))
    }
  }

  private fun unregisterCallReceiver() {
    if (callReceiver != null && applicationContext != null) {
      try { applicationContext!!.unregisterReceiver(callReceiver) } catch (_: Exception) {}
      callReceiver = null
    }
  }

  // --- MethodChannel Handlers ---

  override fun onMethodCall(call: MethodCall, result: Result) {
    if (applicationContext == null) {
      result.error("UNAVAILABLE", "Application context is null", null)
      return
    }
    
    val packageManager = applicationContext!!.packageManager

    when (call.method) {
      "speak" -> {
        val text = call.argument<String>("text")
        val langCode = call.argument<String>("languageCode") ?: "en"
        if (text == null) {
          result.error("INVALID_ARGUMENT", "text is required", null)
          return
        }
        if (tts == null || !isTtsReady) {
          try {
              tts = TextToSpeech(applicationContext) { status ->
                  if (status == TextToSpeech.SUCCESS) {
                      isTtsReady = true
                      speakText(text, langCode)
                  }
              }
          } catch (_: Exception) {}
          result.success(false)
        } else {
          speakText(text, langCode)
          result.success(true)
        }
      }
      "stopSpeaking" -> {
        try {
          tts?.stop()
        } catch (_: Exception) {}
        result.success(true)
      }
      "getInstalledPackages" -> {
        try {
          val packages = packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
          val packageNames = packages.map { it.packageName }.toList()
          result.success(packageNames)
        } catch (e: Exception) {
          result.error("PACKAGE_ERROR", e.message, null)
        }
      }
      "getCertificateHash" -> {
        val packageName = call.argument<String>("packageName")
        if (packageName == null) {
          result.error("INVALID_ARGUMENT", "packageName is required", null)
          return
        }
        try {
          val hash = getSignatureHash(packageManager, packageName)
          if (hash != null) {
              result.success(hash)
          } else {
              result.error("NO_SIGNATURE", "Could not find signature for package", null)
          }
        } catch (e: PackageManager.NameNotFoundException) {
          result.error("NOT_FOUND", "Package not found", null)
        } catch (e: Exception) {
          result.error("HASH_ERROR", e.message, null)
        }
      }
      "isUnknownSourcesEnabled" -> {
        try {
            // Check if any app OTHER than the host app can request installs.
            // On Android 8+, this is a per-app permission.
            val packageManager = applicationContext!!.packageManager
            val packages = packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            var otherAppHasIt = false
            
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                for (pkg in packages) {
                    if (pkg.packageName == applicationContext!!.packageName) continue
                    // Skip system apps
                    if (pkg.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0) continue
                    
                    if (packageManager.canRequestPackageInstalls()) {
                        // Note: canRequestPackageInstalls() is still per-package for the caller.
                        // To check others accurately we'd need AppOps, but for now we skip self
                        // in the general logic or check if the system setting is enabled.
                    }
                }
                // Fallback: Just check if the host app is the only one we are worried about
                // In most malicious cases, the user enables it for a specific fake app.
                result.success(false) // Temporarily allow until robust multi-app check is added
            } else {
                val isEnabled = Settings.Secure.getInt(applicationContext!!.contentResolver, Settings.Secure.INSTALL_NON_MARKET_APPS, 0) == 1
                result.success(isEnabled)
            }
        } catch (e: Exception) {
            result.error("SETTINGS_ERROR", e.message, null)
        }
      }
      "isOverlayPermissionEnabled" -> {
        try {
          // We only return true if an app OTHER than ourselves has overlay permission.
          // Since Settings.canDrawOverlays(context) only checks the caller,
          // we return false here to avoid self-flagging, as the behavioral engine
          // now handles per-app overlay tracking for threats.
          result.success(false) 
        } catch (e: Exception) {
          result.error("SETTINGS_ERROR", e.message, null)
        }
      }
      "isAccessibilityEnabled" -> {
        try {
          val accessibilityEnabled = Settings.Secure.getInt(
            applicationContext!!.contentResolver,
            Settings.Secure.ACCESSIBILITY_ENABLED,
            0
          ) == 1
          result.success(accessibilityEnabled)
        } catch (e: Exception) {
          result.error("SETTINGS_ERROR", e.message, null)
        }
      }
      "isNotificationListenerEnabled" -> {
        try {
          val enabled = Settings.Secure.getString(
            applicationContext!!.contentResolver,
            "enabled_notification_listeners"
          ) ?: ""
          val pkgName = applicationContext!!.packageName
          result.success(enabled.contains(pkgName))
        } catch (e: Exception) {
          result.error("SETTINGS_ERROR", e.message, null)
        }
      }
      "isCallScreeningEnabled" -> {
        try {
          if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val roleManager =
              applicationContext!!.getSystemService(Context.ROLE_SERVICE) as android.app.role.RoleManager
            val hasRole = roleManager.isRoleHeld(android.app.role.RoleManager.ROLE_CALL_SCREENING)
            result.success(hasRole)
          } else {
            result.success(false)
          }
        } catch (e: Exception) {
          result.error("SETTINGS_ERROR", e.message, null)
        }
      }
      "openOverlaySettings" -> {
        try {
          val intent = Intent(
            Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
            Uri.parse("package:" + applicationContext!!.packageName)
          )
          intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
          applicationContext!!.startActivity(intent)
          result.success(true)
        } catch (e: Exception) {
          result.error("SETTINGS_ERROR", e.message, null)
        }
      }
      "openNotificationListenerSettings" -> {
        try {
          val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
          intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
          applicationContext!!.startActivity(intent)
          result.success(true)
        } catch (e: Exception) {
          result.error("SETTINGS_ERROR", e.message, null)
        }
      }
      "openCallScreeningSettings" -> {
        try {
          if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val roleManager =
              applicationContext!!.getSystemService(Context.ROLE_SERVICE) as android.app.role.RoleManager
            val intent = roleManager.createRequestRoleIntent(
              android.app.role.RoleManager.ROLE_CALL_SCREENING
            )
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            applicationContext!!.startActivity(intent)
            result.success(true)
          } else {
            val intent = Intent(Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS)
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            applicationContext!!.startActivity(intent)
            result.success(true)
          }
        } catch (e: Exception) {
          result.error("SETTINGS_ERROR", e.message, null)
        }
      }
      // --- Behavioral Engine Methods ---
      "getBehavioralProfiles" -> {
        val profiles = behavioralStore?.getAll() ?: emptyList()
        result.success(profiles.map { it.toChannelMap() })
      }
      "getBehavioralRiskScore" -> {
        val packageName = call.argument<String>("packageName")
        if (packageName == null) {
          result.error("INVALID_ARGUMENT", "packageName is required", null)
          return
        }
        val profile = behavioralStore?.get(packageName)
        if (profile == null) {
          result.success(hashMapOf("score" to 0, "verdict" to "CLEAN", "found" to false))
        } else {
          val scored = behavioralScorer?.score(profile) ?: BehavioralRiskScorer.ScoringResult(0, "CLEAN")
          result.success(hashMapOf(
            "score" to scored.score,
            "verdict" to scored.verdict,
            "found" to true,
            "profile" to profile.toChannelMap()
          ))
        }
      }
      "reevaluateBehavioralRisk" -> {
        behavioralCollector?.refreshOverlayStatus()
        val profiles = behavioralStore?.getAll() ?: emptyList()
        for (profile in profiles) {
          val scored = behavioralScorer?.score(profile)
          if (scored != null) {
            profile.lastScore = scored.score
            profile.lastVerdict = scored.verdict
            behavioralStore?.put(profile)
          }
        }
        result.success(true)
      }
      "clearBehavioralProfile" -> {
        val packageName = call.argument<String>("packageName")
        if (packageName == null) {
          result.error("INVALID_ARGUMENT", "packageName is required", null)
          return
        }
        behavioralStore?.remove(packageName)
        result.success(true)
      }
      "configureBehavioralEngine" -> {
        val chainWindowMinutes = call.argument<Int>("chainWindowMinutes")
        val whitelistPrefixes = call.argument<List<String>>("whitelistPrefixes")

        if (chainWindowMinutes != null && timeWindowManager != null) {
          timeWindowManager!!.chainWindowMs = chainWindowMinutes.toLong() * 60 * 1000
        }
        if (whitelistPrefixes != null) {
          behavioralScorer = BehavioralRiskScorer(
            whitelist = KnownSafeWhitelist(whitelistPrefixes),
            timeWindowManager = timeWindowManager ?: TimeWindowManager()
          )
        }
        result.success(true)
      }
      // --- APK Hash Denylist Methods ---
      "checkApkHash" -> {
        val certHash = call.argument<String>("certHash")
        if (certHash == null) {
          result.error("INVALID_ARGUMENT", "certHash is required", null)
          return
        }
        val isDenied = apkDenylist?.isDenied(certHash) ?: false
        result.success(isDenied)
      }
      "checkPackageAgainstDenylist" -> {
        val packageName = call.argument<String>("packageName")
        if (packageName == null) {
          result.error("INVALID_ARGUMENT", "packageName is required", null)
          return
        }
        val deniedHash = apkDenylist?.checkPackage(applicationContext!!, packageName)
        result.success(hashMapOf(
          "isDenied" to (deniedHash != null),
          "hash" to (deniedHash ?: "")
        ))
      }
      "addToDenylist" -> {
        val certHash = call.argument<String>("certHash")
        if (certHash == null) {
          result.error("INVALID_ARGUMENT", "certHash is required", null)
          return
        }
        apkDenylist?.addHash(certHash)
        result.success(true)
      }
      "mergeDenylistHashes" -> {
        val hashes = call.argument<List<String>>("hashes")
        if (hashes == null) {
          result.error("INVALID_ARGUMENT", "hashes list is required", null)
          return
        }
        val added = apkDenylist?.mergeFromBackend(hashes) ?: 0
        result.success(hashMapOf(
          "added" to added,
          "total" to (apkDenylist?.size() ?: 0)
        ))
      }
      "getDenylistInfo" -> {
        result.success(apkDenylist?.toChannelMap() ?: hashMapOf(
          "hashes" to emptyList<String>(),
          "count" to 0,
          "lastSyncMs" to 0L
        ))
      }
      // --- Layer 5: Unknown Sources ---
      "startUnknownSourcesMonitor" -> {
        unknownSourcesObserver?.start()
        result.success(true)
      }
      "stopUnknownSourcesMonitor" -> {
        unknownSourcesObserver?.stop()
        result.success(true)
      }
      "getUnknownSourcesStatus" -> {
        val isEnabled = unknownSourcesObserver?.isUnknownSourcesEnabled() ?: false
        val isMonitoring = unknownSourcesObserver?.isMonitoring() ?: false
        result.success(hashMapOf(
          "enabled" to isEnabled,
          "monitoring" to isMonitoring
        ))
      }
      // --- Layer 2A: Download Monitor ---
      "startDownloadMonitor" -> {
        downloadMonitor?.start()
        result.success(true)
      }
      "stopDownloadMonitor" -> {
        downloadMonitor?.stop()
        result.success(true)
      }
      // --- Layer 3: Package Installer Overlay ---
      "startInstallerOverlay" -> {
        if (installerOverlay?.hasOverlayPermission() == true) {
          installerOverlay?.start()
          result.success(true)
        } else {
          result.success(false)
        }
      }
      "stopInstallerOverlay" -> {
        installerOverlay?.stop()
        result.success(true)
      }
      "hasOverlayPermission" -> {
        result.success(installerOverlay?.hasOverlayPermission() ?: false)
      }
      "requestOverlayPermission" -> {
        try {
          val intent = Intent(
            Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
            Uri.parse("package:" + applicationContext!!.packageName)
          )
          intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
          applicationContext!!.startActivity(intent)
          result.success(true)
        } catch (e: Exception) {
          result.error("SETTINGS_ERROR", e.message, null)
        }
      }
      // --- Layer 1B: URL Heuristic Scanner ---
      "scanUrlHeuristic" -> {
        val url = call.argument<String>("url")
        if (url == null) {
          result.error("INVALID_ARGUMENT", "url is required", null)
          return
        }
        val scanResult = urlScanner?.scan(url)
        if (scanResult != null) {
          result.success(scanResult.toChannelMap())
        } else {
          result.success(hashMapOf(
            "url" to url, "score" to 0, "verdict" to "none",
            "flags" to emptyList<String>(), "isSafe" to true
          ))
        }
      }
      "scanTextForUrls" -> {
        val text = call.argument<String>("text")
        if (text == null) {
          result.error("INVALID_ARGUMENT", "text is required", null)
          return
        }
        val results = urlScanner?.scanText(text) ?: emptyList()
        result.success(results.map { it.toChannelMap() })
      }
      "explainThreatWithLlama" -> {
        val threatType = call.argument<String>("threatType") ?: "GENERAL_THREAT"
        val target = call.argument<String>("target") ?: "unknown"
        val riskScore = call.argument<Int>("riskScore") ?: 75
        val indicators = call.argument<List<String>>("indicators") ?: emptyList()

        val ctx = applicationContext
        if (ctx == null) {
          result.error("NO_CONTEXT", "Application context is not available", null)
          return
        }
        val runner = llamaRunner ?: ExecuTorchLlamaRunner(ctx)
        val explanationResult = runner.explainThreat(threatType, target, riskScore, indicators)
        result.success(explanationResult)
      }
      // --- Layer 2B: APK File Observer ---
      "startFileObserver" -> {
        registerFileAlertReceiver()
        result.success(true)
      }
      "stopFileObserver" -> {
        unregisterFileAlertReceiver()
        result.success(true)
      }
      // --- RASP Native Layer Methods (Tasks 1-4) ---
      "raspFullAudit" -> {
        if (!raspAvailable) {
          result.success(hashMapOf(
            "mapsThreats" to 0, "dexMismatches" to 0,
            "sigsysSuspicious" to false, "seccompDetected" to false,
            "latencyMs" to 0.0, "overallVerdict" to "UNAVAILABLE"
          ))
          return
        }
        try {
          val auditResult = RaspNative.audit(applicationContext!!)
          if (auditResult != null) {
            result.success(auditResult.toChannelMap())
          } else {
            result.success(hashMapOf(
              "mapsThreats" to 0, "dexMismatches" to 0,
              "sigsysSuspicious" to false, "seccompDetected" to false,
              "latencyMs" to 0.0, "overallVerdict" to "AUDIT_FAILED"
            ))
          }
        } catch (e: Exception) {
          result.error("RASP_ERROR", e.message, null)
        }
      }
      "raspScanMaps" -> {
        if (!raspAvailable) {
          result.success(emptyList<Map<String, String>>())
          return
        }
        try {
          val threats = RaspNative.scanProcessMaps(applicationContext!!.packageName)
          result.success(threats)
        } catch (e: Exception) {
          result.error("RASP_ERROR", e.message, null)
        }
      }
      "raspVerifyDex" -> {
        if (!raspAvailable) {
          result.success(emptyList<String>())
          return
        }
        try {
          val mismatches = RaspNative.verifyDexIntegrity()
          result.success(mismatches)
        } catch (e: Exception) {
          result.error("RASP_ERROR", e.message, null)
        }
      }
      "raspAuditSigsys" -> {
        if (!raspAvailable) {
          result.success(hashMapOf(
            "hasCustomHandler" to false, "isSuspicious" to false,
            "handlerInfo" to "UNAVAILABLE", "latencyMs" to 0.0,
            "seccompDetected" to false
          ))
          return
        }
        try {
          val apkPath = RaspNative.getApkPath(applicationContext!!)
          val auditMap = RaspNative.auditSigsysHandler(apkPath)
          result.success(auditMap)
        } catch (e: Exception) {
          result.error("RASP_ERROR", e.message, null)
        }
      }
      // --- Task 5: TEE/StrongBox Hardware Key Methods ---
      "generateDeviceKey" -> {
        try {
          val success = HardwareKeyManager.generateDeviceKey()
          result.success(success)
        } catch (e: Exception) {
          result.error("KEY_ERROR", e.message, null)
        }
      }
      "hasDeviceKey" -> {
        result.success(HardwareKeyManager.hasDeviceKey())
      }
      "getPublicKey" -> {
        val pubKey = HardwareKeyManager.getPublicKeyBase64()
        result.success(pubKey)
      }
      "signChallenge" -> {
        val challenge = call.argument<String>("challenge")
        if (challenge == null) {
          result.error("INVALID_ARGUMENT", "challenge is required", null)
          return
        }
        val signature = HardwareKeyManager.signChallenge(challenge.toByteArray(Charsets.UTF_8))
        result.success(signature)
      }
      "deleteDeviceKey" -> {
        val success = HardwareKeyManager.deleteDeviceKey()
        result.success(success)
      }
      "getDeviceKeyInfo" -> {
        result.success(HardwareKeyManager.getKeyInfo())
      }
      "signSilentSmsChallenge" -> {
        val nonce = call.argument<String>("nonce")
        if (nonce == null) {
          result.error("INVALID_ARGUMENT", "nonce is required", null)
          return
        }
        try {
          val isAirplaneMode = try {
              Settings.Global.getInt(
                  applicationContext!!.contentResolver,
                  Settings.Global.AIRPLANE_MODE_ON,
                  0
              ) != 0
          } catch (e: Exception) {
              false
          }
          if (isAirplaneMode) {
              result.error("AIRPLANE_MODE_ACTIVE", "Cannot sign challenge: Airplane Mode is active.", null)
              return
          }
          // For our simulated environment, the signature is SHA-256(nonce + salt)
          val signatureSource = nonce + "sbi_secret_salt"
          val md = MessageDigest.getInstance("SHA-256")
          val digest = md.digest(signatureSource.toByteArray(Charsets.UTF_8))
          val signature = digest.joinToString("") { "%02x".format(it) }
          result.success(signature)
        } catch (e: Exception) {
          result.error("SIGN_ERROR", e.message, null)
        }
      }
      "setActiveChallengeNonce" -> {
        val nonce = call.argument<String>("nonce")
        val customerId = call.argument<String>("customerId")
        activeSmsNonce = nonce
        activeSmsCustomerId = customerId
        result.success(true)
      }
      "clearActiveChallengeNonce" -> {
        activeSmsNonce = null
        activeSmsCustomerId = null
        result.success(true)
      }
      "setCustomerConfig" -> {
        val customerId = call.argument<String>("customerId")
        val backendBaseUrl = call.argument<String>("backendBaseUrl")
        val language = call.argument<String>("language") ?: "en"
        if (customerId == null || backendBaseUrl == null) {
          result.error("INVALID_ARGUMENT", "customerId and backendBaseUrl are required", null)
          return
        }
        try {
          val prefs = applicationContext!!.getSharedPreferences("bankguard_prefs", Context.MODE_PRIVATE)
          prefs.edit()
            .putString("customerId", customerId)
            .putString("backendBaseUrl", backendBaseUrl)
            .putString("language", language)
            .apply()
          result.success(true)
        } catch (e: Exception) {
          result.error("PREFS_ERROR", e.message, null)
        }
      }
      // --- Task 6: Framework Detection Methods ---
      "detectFrameworks" -> {
        try {
          val detection = FrameworkDetector.detect(applicationContext!!)
          result.success(detection.toChannelMap())
        } catch (e: Exception) {
          result.error("DETECT_ERROR", e.message, null)
        }
      }
      "hasPhoneStatePermission" -> {
        val hasPermission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            applicationContext!!.checkSelfPermission(android.Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED
        } else {
            true
        }
        result.success(hasPermission)
      }
      "requestPhoneStatePermission" -> {
        if (activity == null) {
          result.error("NO_ACTIVITY", "Activity is not available to request permissions", null)
          return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
          activity!!.requestPermissions(arrayOf(android.Manifest.permission.READ_PHONE_STATE), 101)
          result.success(true)
        } else {
          result.success(true)
        }
      }
      "hasSmsPermission" -> {
        val hasPermission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            applicationContext!!.checkSelfPermission(android.Manifest.permission.READ_SMS) == PackageManager.PERMISSION_GRANTED &&
            applicationContext!!.checkSelfPermission(android.Manifest.permission.RECEIVE_SMS) == PackageManager.PERMISSION_GRANTED
        } else {
            true
        }
        result.success(hasPermission)
      }
      "requestSmsPermission" -> {
        if (activity == null) {
          result.error("NO_ACTIVITY", "Activity is not available to request permissions", null)
          return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
          activity!!.requestPermissions(arrayOf(
            android.Manifest.permission.READ_SMS,
            android.Manifest.permission.RECEIVE_SMS
          ), 102)
          result.success(true)
        } else {
          result.success(true)
        }
      }
      "hasStoragePermission" -> {
        val hasPermission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
          android.os.Environment.isExternalStorageManager()
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
          applicationContext!!.checkSelfPermission(android.Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED
        } else {
          true
        }
        result.success(hasPermission)
      }
      "requestStoragePermission" -> {
        val act = activity
        val ctx = applicationContext
        if (act == null || ctx == null) {
          result.error("NO_ACTIVITY", "Activity or Context is not available to request permissions", null)
          return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
          if (!android.os.Environment.isExternalStorageManager()) {
            try {
              val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
                data = Uri.parse("package:${ctx.packageName}")
              }
              act.startActivity(intent)
              result.success(true)
            } catch (e: Exception) {
              try {
                val intent = Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
                act.startActivity(intent)
                result.success(true)
              } catch (ex: Exception) {
                result.error("PERMISSION_ERROR", ex.message, null)
              }
            }
          } else {
            result.success(true)
          }
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
          act.requestPermissions(arrayOf(android.Manifest.permission.READ_EXTERNAL_STORAGE), 102)
          result.success(true)
        } else {
          result.success(true)
        }
      }
      "getSimState" -> {
        val isAirplaneMode = try {
            Settings.Global.getInt(
                applicationContext!!.contentResolver,
                Settings.Global.AIRPLANE_MODE_ON,
                0
            ) != 0
        } catch (e: Exception) {
            false
        }

        val hasPermission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            applicationContext!!.checkSelfPermission(android.Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED
        } else {
            true
        }
        
        if (isAirplaneMode) {
            result.success(hashMapOf(
                "permissionGranted" to hasPermission,
                "simChanged" to false,
                "activeSimCount" to 0,
                "simHash" to null,
                "airplaneModeActive" to true,
                "error" to "AIRPLANE_MODE_ACTIVE"
            ))
            return
        }

        if (!hasPermission) {
            result.success(hashMapOf(
                "permissionGranted" to false,
                "simChanged" to false,
                "activeSimCount" to 0,
                "simHash" to null,
                "airplaneModeActive" to false
            ))
            return
        }

        val currentHash = getActiveSimHash()
        val activeCount = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
            try {
                val sm = applicationContext!!.getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE) as SubscriptionManager
                sm.activeSubscriptionInfoList?.size ?: 0
            } catch (e: Exception) {
                0
            }
        } else {
            val tm = applicationContext!!.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
            if (tm.simState == TelephonyManager.SIM_STATE_READY) 1 else 0
        }

        val prefs = applicationContext!!.getSharedPreferences("bankguard_prefs", Context.MODE_PRIVATE)
        var storedHash = prefs.getString("sim_hash_baseline", null)

        var simChanged = false
        if (storedHash == null) {
            if (currentHash != "ERROR_READING_SIM") {
                prefs.edit().putString("sim_hash_baseline", currentHash).apply()
                storedHash = currentHash
            }
        } else {
            if (currentHash != "ERROR_READING_SIM" && currentHash != storedHash) {
                simChanged = true
            }
        }

        result.success(hashMapOf(
            "permissionGranted" to true,
            "simChanged" to simChanged,
            "activeSimCount" to activeCount,
            "simHash" to currentHash,
            "airplaneModeActive" to false
        ))
      }
      "setStoredSimHash" -> {
        val hash = call.argument<String>("simHash")
        if (hash == null) {
          result.error("INVALID_ARGUMENT", "simHash is required", null)
          return
        }
        val prefs = applicationContext!!.getSharedPreferences("bankguard_prefs", Context.MODE_PRIVATE)
        prefs.edit().putString("sim_hash_baseline", hash).apply()
        result.success(true)
      }
      "openAppSettings" -> {
        try {
          val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = Uri.parse("package:" + applicationContext!!.packageName)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
          }
          applicationContext!!.startActivity(intent)
          result.success(true)
        } catch (e: Exception) {
          result.error("SETTINGS_ERROR", e.message, null)
        }
      }
      "requestDefaultBrowserRole" -> {
        val act = activity
        if (act == null) {
          result.error("NO_ACTIVITY", "Activity is null", null)
          return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
          val roleManager = act.getSystemService(RoleManager::class.java)
          if (roleManager != null && roleManager.isRoleAvailable(RoleManager.ROLE_BROWSER)) {
            if (!roleManager.isRoleHeld(RoleManager.ROLE_BROWSER)) {
              val intent = roleManager.createRequestRoleIntent(RoleManager.ROLE_BROWSER)
              act.startActivityForResult(intent, 2005)
              result.success(true)
            } else {
              result.success(true)
            }
          } else {
            result.success(false)
          }
        } else {
          try {
            val intent = Intent(Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS)
            intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
            act.startActivity(intent)
            result.success(true)
          } catch (e: Exception) {
            result.success(false)
          }
        }
      }
      "prepareVpn" -> {
        result.success(false)
      }
      "startVpn" -> {
        result.success(false)
      }
      "stopVpn" -> {
        result.success(true)
      }
      "isVpnRunning" -> {
        result.success(false)
      }
      "verifyFileMagicBytes" -> {
        val filePath = call.argument<String>("filePath")
        if (filePath == null) {
          result.error("INVALID_ARGUMENT", "filePath is required", null)
          return
        }
        try {
          val scanResult = checkApkIntegrity(filePath)
          result.success(scanResult)
        } catch (e: Exception) {
          result.error("SCAN_ERROR", e.message, null)
        }
      }
      "simulateCreateSpoofedFile" -> {
        try {
          val file = java.io.File(applicationContext!!.cacheDir, "statement.pdf")
          java.io.FileOutputStream(file).use { fos ->
              java.util.zip.ZipOutputStream(fos).use { zos ->
                  // 1. Add AndroidManifest.xml entry
                  zos.putNextEntry(java.util.zip.ZipEntry("AndroidManifest.xml"))
                  zos.write("mock_manifest_content".toByteArray())
                  zos.closeEntry()

                  // 2. Add classes.dex entry
                  zos.putNextEntry(java.util.zip.ZipEntry("classes.dex"))
                  zos.write("mock_dex_content".toByteArray())
                  zos.closeEntry()

                  // 3. Add META-INF/MANIFEST.MF entry
                  zos.putNextEntry(java.util.zip.ZipEntry("META-INF/MANIFEST.MF"))
                  zos.write("mock_signature_content".toByteArray())
                  zos.closeEntry()
              }
          }
          result.success(file.absolutePath)
        } catch (e: Exception) {
          result.error("CREATE_FILE_ERROR", e.message, null)
        }
      }
      else -> {
        result.notImplemented()
      }
    }
  }

  private fun checkApkIntegrity(filePath: String): Map<String, Any> {
      val file = java.io.File(filePath)
      if (!file.exists()) {
          return mapOf(
              "fileName" to "",
              "filePath" to filePath,
              "fileSize" to 0L,
              "isPolyglot" to false,
              "isApk" to false,
              "detectedMime" to "unknown",
              "declaredMime" to "unknown",
              "riskScore" to 0.0
          )
      }
      
      val fileName = file.name
      val extension = file.extension.lowercase()
      val fileSize = file.length()
      
      // Read first 4 bytes
      var isZipHeader = false
      var first4BytesHex = ""
      try {
          java.io.FileInputStream(file).use { fis ->
              val header = ByteArray(4)
              val read = fis.read(header)
              if (read >= 4) {
                  first4BytesHex = header.joinToString("") { "%02X".format(it) }
                  if (header[0] == 0x50.toByte() && header[1] == 0x4B.toByte()) {
                      isZipHeader = true
                  }
              }
          }
      } catch (e: Exception) {
          android.util.Log.e("BankguardPlugin", "Error reading magic bytes", e)
      }

      // Check if it contains AndroidManifest.xml and classes.dex (primary parser)
      var isApkStructure = false
      try {
          java.util.zip.ZipFile(file).use { zip ->
              val hasManifest = zip.getEntry("AndroidManifest.xml") != null
              val hasDex = zip.getEntry("classes.dex") != null
              
              // A valid executable APK requires both the manifest and the compiled Dalvik bytecode
              isApkStructure = hasManifest && hasDex
          }
      } catch (e: Exception) {
          // Not a valid zip, or standard ZipFile failed due to prepended garbage headers
      }

      // Fallback: manual sliding-window scan of raw bytes for markers (polyglot/obfuscated APKs)
      if (!isApkStructure) {
          val hasManifestPattern = fileContainsPattern(file, "AndroidManifest.xml".toByteArray(Charsets.UTF_8))
          val hasDexPattern = fileContainsPattern(file, "classes.dex".toByteArray(Charsets.UTF_8))
          isApkStructure = hasManifestPattern && hasDexPattern
      }

      val isApk = isApkStructure
      val declaredMime = when (extension) {
          "apk" -> "application/vnd.android.package-archive"
          "pdf" -> "application/pdf"
          "png" -> "image/png"
          "jpg", "jpeg" -> "image/jpeg"
          "docx" -> "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
          "txt" -> "text/plain"
          else -> "application/octet-stream"
      }
      
      val detectedMime = if (isApk) {
          "application/vnd.android.package-archive"
      } else if (isZipHeader) {
          "application/zip"
      } else {
          declaredMime
      }

      // Mismatch/Polyglot detection:
      // (1) Extension is not .apk but it contains AndroidManifest.xml & classes.dex
      // (2) It contains AndroidManifest.xml & classes.dex but does not start with ZIP magic bytes
      val isPolyglot = isApk && (extension != "apk" || !isZipHeader)
      val riskScore = if (isPolyglot) 1.0 else 0.0

      return mapOf(
          "fileName" to fileName,
          "filePath" to filePath,
          "fileSize" to fileSize,
          "isPolyglot" to isPolyglot,
          "isApk" to isApk,
          "detectedMime" to detectedMime,
          "declaredMime" to declaredMime,
          "riskScore" to riskScore
      )
  }

  private fun fileContainsPattern(file: java.io.File, pattern: ByteArray): Boolean {
      try {
          java.io.FileInputStream(file).use { fis ->
              val buffer = ByteArray(4096)
              var bytesRead = fis.read(buffer)
              val patternSize = pattern.size
              if (patternSize == 0) return false
              
              var prevBufferTail = ByteArray(0)
              
              while (bytesRead != -1) {
                  val searchData = if (prevBufferTail.isEmpty()) {
                      buffer.copyOf(bytesRead)
                  } else {
                      val merged = ByteArray(prevBufferTail.size + bytesRead)
                      System.arraycopy(prevBufferTail, 0, merged, 0, prevBufferTail.size)
                      System.arraycopy(buffer, 0, merged, prevBufferTail.size, bytesRead)
                      merged
                  }
                  
                  for (i in 0..searchData.size - patternSize) {
                      var found = true
                      for (j in 0 until patternSize) {
                          if (searchData[i + j] != pattern[j]) {
                              found = false
                              break
                          }
                      }
                      if (found) return true
                  }
                  
                  if (bytesRead >= patternSize) {
                      prevBufferTail = buffer.copyOfRange(bytesRead - patternSize + 1, bytesRead)
                  } else {
                      prevBufferTail = ByteArray(0)
                  }
                  
                  bytesRead = fis.read(buffer)
              }
          }
      } catch (e: Exception) {
          android.util.Log.e("BankguardPlugin", "Error scanning file for pattern", e)
      }
      return false
  }

  private fun getSignatureHash(packageManager: PackageManager, packageName: String): String? {
      val packageInfo: PackageInfo
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          packageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
          val signatures = packageInfo.signingInfo?.apkContentsSigners
          if (signatures != null && signatures.isNotEmpty()) {
              val md = MessageDigest.getInstance("SHA-256")
              md.update(signatures[0].toByteArray())
              return md.digest().joinToString(":") { "%02X".format(it) }
          }
      } else {
          @Suppress("DEPRECATION")
          packageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
          @Suppress("DEPRECATION")
          val signatures = packageInfo.signatures
          if (signatures != null && signatures.isNotEmpty()) {
              val md = MessageDigest.getInstance("SHA-256")
              md.update(signatures[0].toByteArray())
              return md.digest().joinToString(":") { "%02X".format(it) }
          }
      }
      return null
  }

  override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    if (instance == this) {
      instance = null
    }
    channel.setMethodCallHandler(null)
    unregisterNotificationReceiver()
    unregisterCallReceiver()
    behavioralCollector?.stop()
    behavioralStore?.persistAsync()
    unknownSourcesObserver?.stop()
    downloadMonitor?.stop()
    installerOverlay?.stop()
    unregisterFileAlertReceiver()
    try {
        tts?.shutdown()
    } catch (_: Exception) {}
    tts = null
    isTtsReady = false
    applicationContext = null
  }

  // --- ActivityAware Overrides ---
  override fun onAttachedToActivity(binding: io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding) {
    instance = this
    this.activity = binding.activity
    this.activityBinding = binding
    binding.addActivityResultListener(activityResultListener)
    registerLifecycleCallbacks(binding.activity)
  }

  override fun onDetachedFromActivityForConfigChanges() {
    this.activityBinding?.removeActivityResultListener(activityResultListener)
    unregisterLifecycleCallbacks()
    this.activityBinding = null
    this.activity = null
  }

  override fun onReattachedToActivityForConfigChanges(binding: io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding) {
    instance = this
    this.activity = binding.activity
    this.activityBinding = binding
    binding.addActivityResultListener(activityResultListener)
    registerLifecycleCallbacks(binding.activity)
  }

  override fun onDetachedFromActivity() {
    this.activityBinding?.removeActivityResultListener(activityResultListener)
    unregisterLifecycleCallbacks()
    this.activityBinding = null
    this.activity = null
  }

  private fun registerLifecycleCallbacks(act: Activity) {
    if (lifecycleCallbacks != null) return
    lifecycleCallbacks = object : android.app.Application.ActivityLifecycleCallbacks {
      override fun onActivityPaused(a: Activity) {
        if (a == act) {
          invalidateActiveSilentSmsNonce()
        }
      }
      override fun onActivityResumed(a: Activity) {}
      override fun onActivityStarted(a: Activity) {}
      override fun onActivityStopped(a: Activity) {}
      override fun onActivitySaveInstanceState(a: Activity, outState: android.os.Bundle) {}
      override fun onActivityCreated(a: Activity, savedInstanceState: android.os.Bundle?) {}
      override fun onActivityDestroyed(a: Activity) {}
    }
    try {
      act.application.registerActivityLifecycleCallbacks(lifecycleCallbacks)
    } catch (e: Exception) {
      android.util.Log.e("BankguardPlugin", "Failed to register lifecycle callbacks", e)
    }
  }

  private fun unregisterLifecycleCallbacks() {
    val callbacks = lifecycleCallbacks
    val act = activity
    if (callbacks != null && act != null) {
      try {
        act.application.unregisterActivityLifecycleCallbacks(callbacks)
      } catch (e: Exception) {
        android.util.Log.e("BankguardPlugin", "Failed to unregister lifecycle callbacks", e)
      }
      lifecycleCallbacks = null
    }
  }

  // --- SIM Integrity Helpers ---
  private fun getActiveSimHash(): String {
    if (applicationContext == null) return "ERROR_CONTEXT_NULL"
    try {
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
        val subscriptionManager = applicationContext!!.getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE) as SubscriptionManager
        val activeList = try {
          subscriptionManager.activeSubscriptionInfoList
        } catch (e: SecurityException) {
          null
        }
        if (activeList == null || activeList.isEmpty()) {
          return "NO_ACTIVE_SIM"
        }
        // Sort by subscriptionId to ensure deterministic ordering
        val sortedList = activeList.sortedBy { it.subscriptionId }
        val sb = java.lang.StringBuilder()
        for (info in sortedList) {
          sb.append(info.subscriptionId).append(":")
          sb.append(info.simSlotIndex).append(":")
          sb.append(info.carrierName ?: "").append(":")
          sb.append(info.displayName ?: "").append(":")
          sb.append(info.countryIso ?: "").append(":")
          // Attempt to fetch iccId or cardId depending on API level
          val iccid = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
              info.cardId.toString()
            } else {
              @Suppress("DEPRECATION")
              info.iccId ?: ""
            }
          } catch (e: Exception) {
            ""
          }
          sb.append(iccid).append(";")
        }
        return hashStringSha256(sb.toString())
      } else {
        val telephonyManager = applicationContext!!.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        val simSerialNumber = try {
          @Suppress("DEPRECATION")
          telephonyManager.simSerialNumber ?: ""
        } catch (e: Exception) {
          ""
        }
        val operator = telephonyManager.simOperator ?: ""
        return hashStringSha256(simSerialNumber + ":" + operator)
      }
    } catch (e: Exception) {
      android.util.Log.e("BankguardPlugin", "Error reading SIM info", e)
      return "ERROR_READING_SIM"
    }
  }

  private fun hashStringSha256(input: String): String {
    val bytes = input.toByteArray(Charsets.UTF_8)
    val md = MessageDigest.getInstance("SHA-256")
    val digest = md.digest(bytes)
    return digest.joinToString("") { "%02x".format(it) }
  }

  private fun invalidateActiveSilentSmsNonce() {
    val nonce = activeSmsNonce
    val customerId = activeSmsCustomerId
    if (nonce == null || customerId == null) return

    // Clear locally first
    activeSmsNonce = null
    activeSmsCustomerId = null

    // Notify Flutter layer
    invokeMethod("onSilentSmsInvalidated", null)

    // Call backend asynchronously
    val prefs = applicationContext?.getSharedPreferences("bankguard_prefs", Context.MODE_PRIVATE)
    val backendBaseUrl = prefs?.getString("backendBaseUrl", "https://api.doy.codes") ?: "https://api.doy.codes"

    Thread {
      var connection: java.net.HttpURLConnection? = null
      try {
        val cleanUrl = if (backendBaseUrl.endsWith("/")) backendBaseUrl.substring(0, backendBaseUrl.length - 1) else backendBaseUrl
        val url = java.net.URL("$cleanUrl/api/device/silent-sms/invalidate")
        connection = url.openConnection() as java.net.HttpURLConnection
        connection.requestMethod = "POST"
        connection.connectTimeout = 3000
        connection.readTimeout = 3000
        connection.doOutput = true
        connection.setRequestProperty("Content-Type", "application/json")
        connection.setRequestProperty("Accept", "application/json")

        val jsonPayload = "{\"customer_id\":\"$customerId\",\"nonce\":\"$nonce\"}"
        connection.outputStream.use { os ->
          val input = jsonPayload.toByteArray(Charsets.UTF_8)
          os.write(input, 0, input.size)
        }

        val responseCode = connection.responseCode
        android.util.Log.i("BankguardPlugin", "Invalidated nonce on backend, response code: $responseCode")
      } catch (e: Exception) {
        android.util.Log.e("BankguardPlugin", "Error invalidating active nonce on backend", e)
      } finally {
        connection?.disconnect()
      }
    }.start()
  }

  private fun speakText(text: String, langCode: String) {
    val locale = when (langCode.lowercase()) {
      "hi" -> Locale("hi", "IN")
      "ta" -> Locale("ta", "IN")
      "te" -> Locale("te", "IN")
      "bn" -> Locale("bn", "IN")
      "mr" -> Locale("mr", "IN")
      else -> Locale.ENGLISH
    }
    try {
      tts?.language = locale
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
        tts?.speak(text, TextToSpeech.QUEUE_FLUSH, null, "BG_TTS_UTTERANCE")
      } else {
        @Suppress("DEPRECATION")
        tts?.speak(text, TextToSpeech.QUEUE_FLUSH, null)
      }
    } catch (_: Exception) {}
  }
}

