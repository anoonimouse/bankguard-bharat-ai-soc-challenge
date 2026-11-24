package com.bankguard.sdk

import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.LinearLayout
import android.widget.TextView

/**
 * Floating Security Badge (Overlay Badge).
 *
 * Displays a lightweight, non-intrusive floating pill over the active screen
 * when a scam notification or URL threat is detected. Clicking the badge
 * launches the host banking app into the foreground.
 *
 * Requires SYSTEM_ALERT_WINDOW permission.
 */
class FloatingSecurityBadge(private val context: Context) {
    private var windowManager: WindowManager? = null
    private var badgeView: View? = null
    private var isShowing = false
    private val handler = Handler(Looper.getMainLooper())

    companion object {
        @Volatile
        private var instance: FloatingSecurityBadge? = null

        fun getInstance(context: Context): FloatingSecurityBadge {
            return instance ?: synchronized(this) {
                instance ?: FloatingSecurityBadge(context.applicationContext).also { instance = it }
            }
        }
    }

    /** Check if overlay permission is enabled. */
    fun hasOverlayPermission(): Boolean {
        return Settings.canDrawOverlays(context)
    }

    /** Show the floating badge. Run on UI thread. */
    fun show(category: String, messageText: String) {
        handler.post {
            if (isShowing) {
                // If already showing, update the view content or skip
                return@post
            }
            if (!hasOverlayPermission()) {
                android.util.Log.w("BANKGUARD_BADGE", "Cannot show FloatingSecurityBadge: permission missing")
                return@post
            }

            try {
                windowManager = context.getSystemService(Context.WINDOW_SERVICE) as? WindowManager
                if (windowManager == null) return@post

                val params = createLayoutParams()
                val layout = createBadgeLayout(category)

                windowManager!!.addView(layout, params)
                badgeView = layout
                isShowing = true
                android.util.Log.i("BANKGUARD_BADGE", "FloatingSecurityBadge overlay displayed successfully")
            } catch (e: Exception) {
                android.util.Log.e("BANKGUARD_BADGE", "Failed to add FloatingSecurityBadge view: ${e.message}")
                isShowing = false
            }
        }
    }

    /** Dismiss the floating badge. Run on UI thread. */
    fun dismiss() {
        handler.post {
            if (!isShowing || badgeView == null || windowManager == null) return@post
            try {
                windowManager!!.removeView(badgeView)
                android.util.Log.i("BANKGUARD_BADGE", "FloatingSecurityBadge overlay dismissed")
            } catch (e: Exception) {
                android.util.Log.e("BANKGUARD_BADGE", "Error removing FloatingSecurityBadge: ${e.message}")
            }
            badgeView = null
            isShowing = false
        }
    }

    private fun dpToPx(dp: Int): Int {
        return TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP,
            dp.toFloat(),
            context.resources.displayMetrics
        ).toInt()
    }

    /** Create the layout programmatically with a premium look. */
    private fun createBadgeLayout(category: String): LinearLayout {
        val root = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dpToPx(14), dpToPx(10), dpToPx(14), dpToPx(10))
        }

        // Draw a premium background drawable (dark slate background with a red border)
        val backgroundDrawable = GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            cornerRadius = dpToPx(24).toFloat()
            setColor(Color.parseColor("#1E293B")) // Slate 800
            setStroke(dpToPx(2), Color.parseColor("#EF4444")) // Red 500 border
        }
        root.background = backgroundDrawable

        // 1. Alert Icon TextView
        val iconView = TextView(context).apply {
            text = "[!]"
            textSize = 16f
            gravity = Gravity.CENTER
        }
        root.addView(iconView)

        // 2. Text Container / Label
        val textContainer = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            val layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                leftMargin = dpToPx(8)
                rightMargin = dpToPx(12)
            }
            this.layoutParams = layoutParams
        }

        val titleView = TextView(context).apply {
            text = "BankGuard Alert"
            setTextColor(Color.parseColor("#EF4444")) // Red 500
            textSize = 12f
            setTypeface(null, Typeface.BOLD)
        }
        textContainer.addView(titleView)

        val descView = TextView(context).apply {
            text = "Scam Detected. Tap to secure."
            setTextColor(Color.WHITE)
            textSize = 13f
            setTypeface(null, Typeface.NORMAL)
        }
        textContainer.addView(descView)

        root.addView(textContainer)

        // 3. Close button ('✕')
        val closeBtn = TextView(context).apply {
            text = "✕"
            setTextColor(Color.parseColor("#94A3B8")) // Slate 400
            textSize = 14f
            setTypeface(null, Typeface.BOLD)
            setPadding(dpToPx(8), dpToPx(4), dpToPx(8), dpToPx(4))
            setOnClickListener {
                dismiss()
            }
        }
        root.addView(closeBtn)

        // Main pill tap: launch host banking app and dismiss badge
        root.setOnClickListener {
            dismiss()
            try {
                val launchIntent = context.packageManager.getLaunchIntentForPackage(context.packageName)
                if (launchIntent != null) {
                    launchIntent.addFlags(
                        Intent.FLAG_ACTIVITY_NEW_TASK or
                        Intent.FLAG_ACTIVITY_SINGLE_TOP or
                        Intent.FLAG_ACTIVITY_CLEAR_TOP
                    )
                    context.startActivity(launchIntent)
                    android.util.Log.i("BANKGUARD_BADGE", "Host app promoted via FloatingSecurityBadge click")
                } else {
                    android.util.Log.e("BANKGUARD_BADGE", "Could not find launch intent for ${context.packageName}")
                }
            } catch (e: Exception) {
                android.util.Log.e("BANKGUARD_BADGE", "Failed to launch host app: ${e.message}")
            }
        }

        return root
    }

    @Suppress("DEPRECATION")
    private fun createLayoutParams(): WindowManager.LayoutParams {
        val layoutType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            WindowManager.LayoutParams.TYPE_SYSTEM_ALERT
        }

        return WindowManager.LayoutParams(
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            layoutType,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
            WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL or
            WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.CENTER_HORIZONTAL
            y = dpToPx(72) // Margins from top of the screen (to clear typical status bar/notch height)
        }
    }
}
