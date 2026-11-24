package com.bankguard.sdk

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
import android.widget.LinearLayout
import android.widget.TextView
import java.util.Locale

object VishingOverlayWindow {
    private var overlayView: View? = null
    private var windowManager: WindowManager? = null
    private var isShowing = false
    private var tts: TextToSpeech? = null
    private var activeLang = "en"
    private var callingNumber = ""

    private var titleView: TextView? = null
    private var messageView: TextView? = null
    private var dismissButton: Button? = null
    private val chipViews = mutableMapOf<String, TextView>()

    private val translations: Map<String, Map<String, String>> = mapOf(
        "en" to mapOf(
            "title" to "Unverified Active Call",
            "message" to "Security Alert: You are currently on an active call with an unverified number.\n\nNever share OTP, MPIN, or Card Details with the caller. SBI will never ask for credentials or request you to transfer funds over a call.",
            "dismiss" to "I Understand"
        ),
        "hi" to mapOf(
            "title" to "अपुष्ट सक्रिय कॉल",
            "message" to "सुरक्षा चेतावनी: आप वर्तमान में एक अपुष्ट नंबर के साथ सक्रिय कॉल पर हैं।\n\nकॉलर के साथ कभी भी ओटीपी, एमपिन या कार्ड विवरण साझा न करें। एसबीआई कभी भी आपसे क्रेडेंशियल नहीं मांगेगा या कॉल पर फंड ट्रांसफर करने का अनुरोध नहीं करेगा।",
            "dismiss" to "मैं समझता हूँ"
        ),
        "mr" to mapOf(
            "title" to "अपुष्ट सक्रिय कॉल",
            "message" to "सुरक्षा चेतावणी: तुम्ही सध्या अपुष्ट क्रमांकासह सक्रिय कॉलवर आहात।\n\nकॉलरसोबत कधीही ओटीपी, एमपिन किंवा कार्ड तपशील सामायिक करू नका। एसबीआई कधीही क्रेडेंशियल मागणार नाही किंवा कॉलवर पैसे पाठवण्यास सांगणार नाही।",
            "dismiss" to "मला समजले"
        ),
        "ta" to mapOf(
            "title" to "சரிபார்க்கப்படாத செயலில் உள்ள அழைப்பு",
            "message" to "பாதுகாப்பு எச்சரிக்கை: நீங்கள் தற்போது சரிபார்க்கப்படாத எண்ணுடன் செயலில் உள்ள அழைப்பில் உள்ளீர்கள்.\n\nஅழைப்பாளருடன் ஒருபோதும் OTP, MPIN அல்லது கார்டு விவரங்களைப் பகிர வேண்டாம். எஸ்பிஐ ஒருபோதும் நற்சான்றிதழ்களைக் கேட்காது அல்லது அழைப்பின் மூலம் பணத்தை மாற்றுமாறு கோராது.",
            "dismiss" to "எனக்கு புரிகிறது"
        ),
        "te" to mapOf(
            "title" to "ధృవీకరించబడని యాక్టివ్ కాల్",
            "message" to "భద్రతా హెచ్చరిక: మీరు ప్రస్తుతం ధృవీకరించబడని నంబర్‌తో యాక్టివ్ కాల్‌లో ఉన్నారు.\n\nకాలర్‌తో ఓటీపీ, ఎంపిన్ లేదా కార్డ్ వివరాలను ఎప్పుడూ పంచుకోవద్దు. ఎస్బీఐ ఎప్పుడూ మీ ఆధారాలను అడగదు లేదా కాల్‌లో డబ్బులు బదిలీ చేయమని కోరదు.",
            "dismiss" to "నాకు అర్థమైంది"
        ),
        "bn" to mapOf(
            "title" to "অযাচাইকৃত সক্রিয় কল",
            "message" to "নিরাপত্তা সতর্কতা: আপনি বর্তমানে একটি অযাচাইকৃত নম্বরের সাথে সক্রিয় কলে আছেন।\n\nকলারের সাথে কখনই ওটিপি, এমপিন বা কার্ডের বিবরণ শেয়ার করবেন না। এসবিআই কখনই আপনার গোপনীয় তথ্য চাইবে না বা কলে টাকা পাঠাতে বলবে না।",
            "dismiss" to "আমি বুঝতে পেরেছি"
        )
    )

    fun show(context: Context, number: String) {
        if (isShowing) return
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (!android.provider.Settings.canDrawOverlays(context)) {
                Log.w("VishingOverlayWindow", "Cannot show vishing overlay: Overlay permission not granted")
                return
            }
        }

        callingNumber = number
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

                val layout = LinearLayout(context).apply {
                    orientation = LinearLayout.VERTICAL
                    setBackgroundColor(Color.parseColor("#FFFFFF"))
                    setPadding(dpToPx(20), dpToPx(20), dpToPx(20), dpToPx(20))
                    
                    val border = GradientDrawable().apply {
                        setColor(Color.parseColor("#FFFFFF"))
                        setStroke(dpToPx(3), Color.parseColor("#DC2626")) // Crimson border
                        cornerRadius = dpToPx(16).toFloat()
                    }
                    background = border
                    elevation = dpToPx(12).toFloat()
                }

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

                val languages = listOf(
                    "en" to "English",
                    "hi" to "हिंदी",
                    "mr" to "मराठी",
                    "ta" to "தமிழ்",
                    "te" to "తెలుగు",
                    "bn" to "বাংলা"
                )

                chipViews.clear()

                for ((code, name) in languages) {
                    val chip = TextView(context).apply {
                        text = name
                        setPadding(dpToPx(12), dpToPx(6), dpToPx(12), dpToPx(6))
                        textSize = 12f
                        typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
                        
                        val chipParams = LinearLayout.LayoutParams(
                            LinearLayout.LayoutParams.WRAP_CONTENT,
                            LinearLayout.LayoutParams.WRAP_CONTENT
                        ).apply {
                            setMargins(0, 0, dpToPx(8), 0)
                        }
                        layoutParams = chipParams
                        
                        setOnClickListener {
                            updateLanguage(context, code)
                        }
                    }
                    langChipsLayout.addView(chip)
                    chipViews[code] = chip
                }

                scrollView.addView(langChipsLayout)
                layout.addView(scrollView)

                val headerLayout = LinearLayout(context).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER_VERTICAL
                    layoutParams = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT
                    ).apply {
                        setMargins(0, 0, 0, dpToPx(14))
                    }
                }

                titleView = TextView(context).apply {
                    textSize = 18f
                    setTextColor(Color.parseColor("#DC2626"))
                    setTypeface(null, Typeface.BOLD)
                    text = translations[activeLang]!!["title"]
                    layoutParams = LinearLayout.LayoutParams(
                        0,
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                        1.0f
                    )
                }

                headerLayout.addView(titleView)
                layout.addView(headerLayout)

                messageView = TextView(context).apply {
                    textSize = 14f
                    setTextColor(Color.parseColor("#1E293B"))
                    setTypeface(null, Typeface.NORMAL)
                    setLineSpacing(0f, 1.25f)
                    text = translations[activeLang]!!["message"]
                    layoutParams = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT
                    ).apply {
                        setMargins(0, 0, 0, dpToPx(18))
                    }
                }
                layout.addView(messageView)

                val actionsLayout = LinearLayout(context).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.END
                }

                dismissButton = Button(context).apply {
                    text = translations[activeLang]!!["dismiss"]
                    setBackgroundColor(Color.parseColor("#DC2626"))
                    setTextColor(Color.WHITE)
                    textSize = 13f
                    setTypeface(null, Typeface.BOLD)
                    setPadding(dpToPx(16), 0, dpToPx(16), 0)
                    
                    val btnParams = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                        dpToPx(40)
                    )
                    layoutParams = btnParams
                    
                    setOnClickListener {
                        dismiss()
                    }
                }
                actionsLayout.addView(dismissButton)
                layout.addView(actionsLayout)

                val params = WindowManager.LayoutParams(
                    WindowManager.LayoutParams.MATCH_PARENT,
                    WindowManager.LayoutParams.WRAP_CONTENT,
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
                    } else {
                        WindowManager.LayoutParams.TYPE_PHONE
                    },
                    WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                            WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON or
                            WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
                            WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON,
                    PixelFormat.TRANSLUCENT
                ).apply {
                    gravity = Gravity.TOP
                    y = dpToPx(50)
                    windowAnimations = android.R.style.Animation_Dialog
                }

                windowManager!!.addView(layout, params)
                overlayView = layout
                isShowing = true

                updateLanguage(context, activeLang)

            } catch (e: Exception) {
                Log.e("VishingOverlayWindow", "Failed to display vishing overlay window: ${e.message}", e)
                isShowing = false
            }
        }
    }

    private fun updateLanguage(context: Context, code: String) {
        try {
            tts?.stop()
        } catch (_: Exception) {}

        activeLang = code
        val tr = translations[code] ?: translations["en"]!!
        
        titleView?.text = tr["title"]
        messageView?.text = tr["message"]
        dismissButton?.text = tr["dismiss"]

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
                setColor(Color.parseColor(if (isSelected) "#DC2626" else "#F1F5F9"))
                setStroke(dpToPx(if (isSelected) 0 else 1), Color.parseColor(if (isSelected) "#00000000" else "#CBD5E1"))
                cornerRadius = dpToPx(16).toFloat()
            }
            view.background = bg
            view.setTextColor(Color.parseColor(if (isSelected) "#FFFFFF" else "#475569"))
            view.setTypeface(null, if (isSelected) Typeface.BOLD else Typeface.NORMAL)
        }

        val textToSpeak = "${tr["title"]}. ${tr["message"]}"
        speakText(context, textToSpeak, code)
    }

    private fun speakText(context: Context, text: String, lang: String) {
        if (tts == null) {
            tts = TextToSpeech(context) { status ->
                if (status == TextToSpeech.SUCCESS) {
                    setTtsLanguage(lang)
                    tts?.speak(text, TextToSpeech.QUEUE_FLUSH, null, null)
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
}
