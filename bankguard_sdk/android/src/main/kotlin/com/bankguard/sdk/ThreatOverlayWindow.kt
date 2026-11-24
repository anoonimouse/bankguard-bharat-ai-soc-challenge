package com.bankguard.sdk

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.speech.tts.TextToSpeech
import android.util.Log
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.HorizontalScrollView
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import java.io.File
import java.util.Locale

object ThreatOverlayWindow {
    private var overlayView: View? = null
    private var windowManager: WindowManager? = null
    private var isShowing = false
    private var tts: TextToSpeech? = null
    private var activeLang = "en"
    private var currentFileName = ""
    private var currentFileExtension = ""

    // Views to update dynamically
    private var titleView: TextView? = null
    private var messageView: TextView? = null
    private var dismissButton: Button? = null
    private var deleteButton: Button? = null
    private var openButton: Button? = null
    private val chipViews = mutableMapOf<String, TextView>()

    // Translation registry for all 6 supported vernacular languages
    private val translations: Map<String, Map<String, String>> = mapOf(
        "en" to mapOf(
            "title" to "BankGuard Threat Alert",
            "message" to "Critical Threat: Disguised installation package (Polyglot APK) detected in your storage:\n\nFile: %s\n\nThis file was renamed to mimic a .%s document, but it contains executable Android code. This is a common method used by fraudsters to bypass security controls. Do NOT open or attempt to install this file.",
            "dismiss" to "I Understand",
            "delete" to "Delete File",
            "stop" to "DON'T INSTALL"
        ),
        "hi" to mapOf(
            "title" to "बैंकगार्ड खतरा चेतावनी",
            "message" to "गंभीर खतरा: आपके स्टोरेज में एक छद्म इंस्टॉलेशन पैकेज (पॉलीग्लॉट APK) पाया गया है:\n\nफ़ाइल: %s\n\nइस फ़ाइल का नाम बदलकर .%s दस्तावेज़ जैसा किया गया है, लेकिन इसमें निष्पादन योग्य एंड्रॉइड कोड है। धोखेबाजों द्वारा सुरक्षा नियंत्रणों को दरकिनार करने के लिए यह एक आम तरीका है। इस फ़ाइल को न खोलें और न ही इंस्टॉल करने का प्रयास करें।",
            "dismiss" to "मैं समझता हूँ",
            "delete" to "फ़ाइल हटाएं",
            "stop" to "इंस्टॉल न करें"
        ),
        "mr" to mapOf(
            "title" to "बँकगार्ड सुरक्षा इशारा",
            "message" to "गंभीर धोका: आपल्या स्टोरेजमध्ये एक छुपे इन्स्टॉलेशन पॅकेज (पॉलीग्लॉट APK) आढळले आहे:\n\nफाईल: %s\n\nया फाईलचे नाव बदलून .%s दस्तऐवजासारखे केले आहे, परंतु यात चालवण्यायोग्य अँड्रॉइड कोड आहे। सुरक्षा नियंत्रण टाळण्यासाठी फसवणूक करणाऱ्यांकडून ही पद्धत वापरली जाते। ही फाईल उघडू नका किंवा इन्स्टॉल करण्याचा प्रयत्न करू नका।",
            "dismiss" to "मला समजले",
            "delete" to "फाईल नष्ट करा",
            "stop" to "इन्स्टॉल करू नका"
        ),
        "ta" to mapOf(
            "title" to "வங்கிபாதுகாப்பு அச்சுறுத்தல் எச்சரிக்கை",
            "message" to "தீவிர அச்சுறுத்தல்: உங்கள் சேமிப்பகத்தில் மறைமுகமான நிறுவல் தொகுப்பு (பாலிங்லாட் APK) கண்டறியப்பட்டுள்ளது:\n\nகோப்பு: %s\n\nஇந்த கோப்பு .%s ஆவணம் போல மறுபெயரிடப்பட்டுள்ளது, ஆனால் இதில் இயக்கக்கூடிய ஆண்ட்ராய்டு குறியீடு உள்ளது. பாதுகாப்பு சோதனைகளைத் தவிர்க்க மோசடி செய்பவர்கள் பயன்படுத்தும் பொதுவான முறை இதுவாகும். இந்த கோப்பைத் திறக்கவோ அல்லது நிறுவவோ வேண்டாம்.",
            "dismiss" to "எனக்கு புரிகிறது",
            "delete" to "கோப்பை நீக்கு",
            "stop" to "நிறுவ வேண்டாம்"
        ),
        "te" to mapOf(
            "title" to "బ్యాంక్‌గార్డ్ ముప్పు హెచ్చరిక",
            "message" to "తీవ్రమైన ముప్పు: మీ స్టోరేజ్‌లో నకిలీ ఇన్‌స్టాలేషన్ ప్యాకేజీ (పాలిగ్లాట్ APK) కనుగోనబడింది:\n\nఫైల్: %s\n\nఈ ఫైల్ .%s పత్రం వలె పేరు మార్చబడింది, కానీ ఇందులో రన్ అయ్యే ఆండ్రాయిడ్ కోడ్ ఉంది. భద్రతా నియంత్రణలను దాటవేయడానికి మోసగాళ్లు ఉపయోగించే సాధారణ పద్ధతి ఇది. ఈ ఫైల్‌ను తెరవకండి లేదా ఇన్‌స్టాల్ చేయడానికి ప్రయత్నించకండి.",
            "dismiss" to "నాకు అర్థమైంది",
            "delete" to "ఫైల్ తొలగించు",
            "stop" to "ఇన్‌స్టాల్ చేయవద్దు"
        ),
        "bn" to mapOf(
            "title" to "ব্যাংকগার্ড হুমকি সতর্কতা",
            "message" to "গুরুতর হুমকি: আপনার স্টোরেজে ছদ্মবেশী ইনস্টলেশন প্যাকেজ (পলিগ্লট APK) সনাক্ত করা হয়েছে:\n\nফাইল: %s\n\nএই ফাইলটির নাম পরিবর্তন করে .%s নথির মতো করা হয়েছে, তবে এতে রান করা যোগ্য অ্যান্ড্রয়েড কোড রয়েছে। নিরাপত্তা নিয়ন্ত্রণ এড়ানোর জন্য প্রতারকদের এটি একটি সাধারণ পদ্ধতি। এই ফাইলটি খুলবেন না বা ইনস্টল করার চেষ্টা করবেন না।",
            "dismiss" to "আমি বুঝতে পেরেছি",
            "delete" to "ফাইল মুছুন",
            "stop" to "ইনস্টল করবেন না"
        )
    )

    fun show(context: Context, fileName: String, fileExtension: String, filePath: String? = null) {
        if (isShowing) return
        
        // Check overlay permission
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (!android.provider.Settings.canDrawOverlays(context)) {
                Log.w("ThreatOverlayWindow", "Cannot show overlay: Permission not granted. Triggering notification fallback.")
                showFallbackNotification(context, fileName, fileExtension)
                return
            }
        }

        currentFileName = fileName
        currentFileExtension = fileExtension

        // Default language based on device settings, fallback to English
        activeLang = "en"
        val systemLocale = Locale.getDefault().language
        if (translations.containsKey(systemLocale)) {
            activeLang = systemLocale
        }

        val mainHandler = android.os.Handler(android.os.Looper.getMainLooper())
        mainHandler.post {
            try {
                windowManager = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
                
                val dpToPx = { dp: Int ->
                    TypedValue.applyDimension(
                        TypedValue.COMPLEX_UNIT_DIP,
                        dp.toFloat(),
                        context.resources.displayMetrics
                    ).toInt()
                }

                // Main light-themed panel
                val layout = LinearLayout(context).apply {
                    orientation = LinearLayout.VERTICAL
                    setBackgroundColor(Color.parseColor("#FFFFFF")) // Pure White
                    setPadding(dpToPx(20), dpToPx(20), dpToPx(20), dpToPx(20))
                    
                    val border = GradientDrawable().apply {
                        setColor(Color.parseColor("#FFFFFF"))
                        setStroke(dpToPx(3), Color.parseColor("#DC2626")) // Thick Crimson Warning Border
                        cornerRadius = dpToPx(16).toFloat()
                    }
                    background = border
                    elevation = dpToPx(12).toFloat()
                }

                // 1. Language selector chips row (Horizontal Scroll View)
                val scrollView = HorizontalScrollView(context).apply {
                    isHorizontalScrollBarEnabled = false
                    layoutParams = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT
                    ).apply {
                        setMargins(0, 0, 0, dpToPx(12))
                    }
                }

                val langChipsLayout = LinearLayout(context).apply {
                    orientation = LinearLayout.HORIZONTAL
                    setPadding(dpToPx(2), dpToPx(2), dpToPx(2), dpToPx(2))
                }
                scrollView.addView(langChipsLayout)
                layout.addView(scrollView)

                val languages = listOf(
                    Pair("en", "English"),
                    Pair("hi", "हिन्दी"),
                    Pair("mr", "मराठी"),
                    Pair("ta", "தமிழ்"),
                    Pair("te", "తెలుగు"),
                    Pair("bn", "বাংলা")
                )

                chipViews.clear()
                languages.forEach { (code, label) ->
                    val chip = TextView(context).apply {
                        text = label
                        setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
                        setPadding(dpToPx(10), dpToPx(6), dpToPx(10), dpToPx(6))
                        gravity = Gravity.CENTER
                        
                        layoutParams = LinearLayout.LayoutParams(
                            LinearLayout.LayoutParams.WRAP_CONTENT,
                            LinearLayout.LayoutParams.WRAP_CONTENT
                        ).apply {
                            setMargins(0, 0, dpToPx(6), 0)
                        }

                        setOnClickListener {
                            updateLanguage(context, code)
                        }
                    }
                    chipViews[code] = chip
                    langChipsLayout.addView(chip)
                }

                // 2. Title Row (Title + Listen Button)
                val titleRow = LinearLayout(context).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER_VERTICAL
                    layoutParams = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT
                    )
                }

                titleView = TextView(context).apply {
                    setTextColor(Color.parseColor("#DC2626")) // Crimson Red 600
                    textSize = 18f
                    setTypeface(null, Typeface.BOLD)
                    layoutParams = LinearLayout.LayoutParams(
                        0,
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                        1.0f
                    )
                }
                titleRow.addView(titleView)

                val playAudioButton = ImageView(context).apply {
                    setImageResource(android.R.drawable.ic_lock_silent_mode_off)
                    setPadding(dpToPx(8), dpToPx(8), dpToPx(8), dpToPx(8))
                    
                    val btnBg = GradientDrawable().apply {
                        setColor(Color.parseColor("#F1F5F9")) // Soft Light Gray
                        cornerRadius = dpToPx(20).toFloat() // Circular button
                        setStroke(dpToPx(1), Color.parseColor("#CBD5E1"))
                    }
                    background = btnBg
                    
                    layoutParams = LinearLayout.LayoutParams(
                        dpToPx(36), // Fixed width
                        dpToPx(36)  // Fixed height
                    ).apply {
                        gravity = Gravity.CENTER_VERTICAL
                    }
                    
                    setOnClickListener {
                        val tr = translations[activeLang] ?: translations["en"]!!
                        val rawMessage = tr["message"] ?: ""
                        val cleanMessage = String.format(rawMessage, currentFileName, currentFileExtension)
                        val textToSpeak = "${tr["title"]}. $cleanMessage"
                        
                        try {
                            tts?.stop()
                        } catch (_: Exception) {}
                        speakText(context, textToSpeak, activeLang)
                    }
                }
                titleRow.addView(playAudioButton)
                layout.addView(titleRow)

                // Divider
                val divider = View(context).apply {
                    setBackgroundColor(Color.parseColor("#E2E8F0")) // Slate 200
                    layoutParams = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        dpToPx(1)
                    ).apply {
                        setMargins(0, dpToPx(10), 0, dpToPx(10))
                    }
                }
                layout.addView(divider)

                // 3. Warning Graphic
                val imageView = ImageView(context).apply {
                    try {
                        val inputStream = context.assets.open("flutter_assets/assets/images/apk_box_warning.png")
                        val bitmap = android.graphics.BitmapFactory.decodeStream(inputStream)
                        setImageBitmap(bitmap)
                        layoutParams = LinearLayout.LayoutParams(
                            LinearLayout.LayoutParams.MATCH_PARENT,
                            dpToPx(110)
                        ).apply {
                            setMargins(0, 0, 0, dpToPx(8))
                        }
                        scaleType = ImageView.ScaleType.FIT_CENTER
                    } catch (e: Exception) {
                        Log.e("ThreatOverlayWindow", "Failed to load warning asset: ${e.message}")
                    }
                }
                layout.addView(imageView)

                // 4. Message Body
                messageView = TextView(context).apply {
                    setTextColor(Color.parseColor("#0F172A")) // Slate 900
                    textSize = 13f
                    gravity = Gravity.LEFT
                }
                layout.addView(messageView)

                // 5. Action Buttons (Dismiss / Delete / Don't Install)
                val buttonsLayout = LinearLayout(context).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER_HORIZONTAL
                    layoutParams = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT
                    ).apply {
                        setMargins(0, dpToPx(16), 0, 0)
                    }
                }

                dismissButton = Button(context).apply {
                    setTextColor(Color.parseColor("#64748B")) // Slate 500
                    setBackgroundColor(Color.TRANSPARENT)
                    textSize = 12f
                    layoutParams = LinearLayout.LayoutParams(
                        0,
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                        1.0f
                    ).apply {
                        setMargins(0, 0, dpToPx(6), 0)
                    }
                    setOnClickListener {
                        dismiss()
                    }
                }
                buttonsLayout.addView(dismissButton)

                if (filePath != null) {
                    deleteButton = Button(context).apply {
                        text = "Delete File"
                        setTextColor(Color.WHITE)
                        val btnBg = GradientDrawable().apply {
                            setColor(Color.parseColor("#EF4444")) // Red 500
                            cornerRadius = dpToPx(6).toFloat()
                        }
                        background = btnBg
                        textSize = 12f
                        layoutParams = LinearLayout.LayoutParams(
                            0,
                            LinearLayout.LayoutParams.WRAP_CONTENT,
                            1.0f
                        ).apply {
                            setMargins(0, 0, dpToPx(6), 0)
                        }
                        setOnClickListener {
                            try {
                                val file = File(filePath)
                                if (file.exists()) {
                                    val deleted = file.delete()
                                    if (deleted) {
                                        context.contentResolver.delete(
                                            android.provider.MediaStore.Files.getContentUri("external"),
                                            "${android.provider.MediaStore.Files.FileColumns.DATA} = ?",
                                            arrayOf(filePath)
                                        )
                                        Toast.makeText(context, "Disguised file deleted successfully!", Toast.LENGTH_LONG).show()
                                    } else {
                                        Toast.makeText(context, "Failed to delete file.", Toast.LENGTH_LONG).show()
                                    }
                                } else {
                                    Toast.makeText(context, "File already deleted.", Toast.LENGTH_SHORT).show()
                                }
                            } catch (e: Exception) {
                                Log.e("ThreatOverlayWindow", "Error deleting file: ${e.message}")
                            }
                            dismiss()
                        }
                    }
                    buttonsLayout.addView(deleteButton)
                }

                openButton = Button(context).apply {
                    setTextColor(Color.WHITE)
                    val btnBg = GradientDrawable().apply {
                        setColor(Color.parseColor("#DC2626")) // Crimson Red 600
                        cornerRadius = dpToPx(6).toFloat()
                    }
                    background = btnBg
                    textSize = 11f
                    setTypeface(null, Typeface.BOLD)
                    layoutParams = LinearLayout.LayoutParams(
                        0,
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                        1.0f
                    )
                    setOnClickListener {
                        dismiss()
                        val launchIntent = context.packageManager.getLaunchIntentForPackage(context.packageName)?.apply {
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                        }
                        context.startActivity(launchIntent)
                    }
                }
                buttonsLayout.addView(openButton)

                layout.addView(buttonsLayout)

                // Layout specifications
                val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
                } else {
                    @Suppress("DEPRECATION")
                    WindowManager.LayoutParams.TYPE_SYSTEM_ALERT
                }

                val width = (context.resources.displayMetrics.widthPixels * 0.9).toInt()
                val params = WindowManager.LayoutParams(
                    width,
                    WindowManager.LayoutParams.WRAP_CONTENT,
                    type,
                    WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL or
                        WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
                    PixelFormat.TRANSLUCENT
                ).apply {
                    gravity = Gravity.CENTER
                }

                windowManager!!.addView(layout, params)
                overlayView = layout
                isShowing = true

                // Update text layouts to default language and auto-play TTS sound
                updateLanguage(context, activeLang)

            } catch (e: Exception) {
                Log.e("ThreatOverlayWindow", "Failed to display threat overlay window: ${e.message}", e)
                isShowing = false
            }
        }
    }

    private fun updateLanguage(context: Context, code: String) {
        // Stop current speech instantly before translating and re-triggering
        try {
            tts?.stop()
        } catch (_: Exception) {}

        activeLang = code
        val tr = translations[code] ?: translations["en"]!!
        
        titleView?.text = tr["title"]
        messageView?.text = String.format(tr["message"] ?: "", currentFileName, currentFileExtension)
        dismissButton?.text = tr["dismiss"]
        deleteButton?.text = tr["delete"]
        openButton?.text = tr["stop"]

        // Stylize selected chip and unselected chips (Light Theme styles)
        val dpToPx = { dp: Int ->
            TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP,
                dp.toFloat(),
                context.resources.displayMetrics
            ).toInt()
        }

        chipViews.forEach { (c, view) ->
            val isSelected = c == code
            val bg = GradientDrawable().apply {
                setColor(Color.parseColor(if (isSelected) "#DC2626" else "#F1F5F9")) // Crimson selected vs Light Slate
                setStroke(dpToPx(if (isSelected) 0 else 1), Color.parseColor(if (isSelected) "#00000000" else "#CBD5E1"))
                cornerRadius = dpToPx(16).toFloat()
            }
            view.background = bg
            view.setTextColor(Color.parseColor(if (isSelected) "#FFFFFF" else "#475569")) // White selected vs Slate unselected
            view.setTypeface(null, if (isSelected) Typeface.BOLD else Typeface.NORMAL)
        }

        // Trigger native TTS to read aloud in the chosen language
        val rawMessage = tr["message"] ?: ""
        val cleanMessage = String.format(rawMessage, currentFileName, currentFileExtension)
        val textToSpeak = "${tr["title"]}. $cleanMessage"
        
        speakText(context, textToSpeak, code)
    }

    private fun speakText(context: Context, text: String, lang: String) {
        if (tts == null) {
            tts = TextToSpeech(context) { status ->
                if (status == TextToSpeech.SUCCESS) {
                    setTtsLanguage(lang)
                    tts?.speak(text, TextToSpeech.QUEUE_FLUSH, null, null)
                } else {
                    Log.e("ThreatOverlayWindow", "Failed to initialize TTS engine")
                }
            }
        } else {
            setTtsLanguage(lang)
            tts?.speak(text, TextToSpeech.QUEUE_FLUSH, null, null)
        }
    }

    private fun setTtsLanguage(lang: String) {
        val locale = when (lang) {
            "hi" -> Locale("hi", "IN")
            "mr" -> Locale("mr", "IN")
            "ta" -> Locale("ta", "IN")
            "te" -> Locale("te", "IN")
            "bn" -> Locale("bn", "IN")
            else -> Locale.US
        }
        tts?.language = locale
    }

    fun dismiss() {
        if (tts != null) {
            try {
                tts?.stop()
                tts?.shutdown()
            } catch (_: Exception) {}
            tts = null
        }

        if (!isShowing || overlayView == null || windowManager == null) return
        val mainHandler = android.os.Handler(android.os.Looper.getMainLooper())
        mainHandler.post {
            try {
                windowManager!!.removeView(overlayView)
            } catch (_: Exception) {}
            overlayView = null
            isShowing = false
            windowManager = null
        }
    }

    private fun showFallbackNotification(context: Context, fileName: String, fileExtension: String) {
        try {
            val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            val channelId = "bankguard_threats"
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val channel = NotificationChannel(
                    channelId,
                    "BankGuard Threat Alerts",
                    NotificationManager.IMPORTANCE_HIGH
                ).apply {
                    description = "Real-time alerts for downloaded threats"
                    enableLights(true)
                    lightColor = android.graphics.Color.RED
                    enableVibration(true)
                }
                notificationManager.createNotificationChannel(channel)
            }

            // Launch the main app with special threat flags to trigger the threat dialog
            val launchIntent = context.packageManager.getLaunchIntentForPackage(context.packageName)?.apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                putExtra("threat_detected", true)
                putExtra("threat_filename", fileName)
                putExtra("threat_extension", fileExtension)
            }
            
            val pendingIntent = PendingIntent.getActivity(
                context,
                1002,
                launchIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )

            val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                Notification.Builder(context, channelId)
            } else {
                @Suppress("DEPRECATION")
                Notification.Builder(context)
            }

            val notification = builder
                .setContentTitle("🚨 BankGuard Critical Alert")
                .setContentText("Disguised threat ($fileExtension) detected: $fileName. Tap to secure your device.")
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentIntent(pendingIntent)
                .setAutoCancel(true)
                .setPriority(Notification.PRIORITY_HIGH)
                .setDefaults(Notification.DEFAULT_ALL)
                .build()

            notificationManager.notify(2004, notification)
            Log.i("ThreatOverlayWindow", "Fallback Notification posted successfully for $fileName")
        } catch (e: Exception) {
            Log.e("ThreatOverlayWindow", "Failed to show fallback notification: ${e.message}", e)
        }
    }
}
