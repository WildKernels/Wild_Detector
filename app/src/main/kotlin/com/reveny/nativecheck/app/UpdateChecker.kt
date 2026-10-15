package com.reveny.nativecheck.app

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.util.Log
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors

/**
 * Update check: on app open, resolve this repo's latest GitHub release tag and
 * compare it with the installed versionCode. If a newer release exists, the
 * dialog just links to the releases page - no in-app download or install.
 *
 * Endpoint is https://github.com/WildKernels/Wild_Detector/releases/latest,
 * which 302-redirects to /releases/tag/vN: one unauthenticated request, no
 * JSON API rate limit. Failures are logged (tag "WildDetector") and silent -
 * the background check must never nag with error toasts.
 */
class UpdateChecker(private val context: Context) {

    fun checkForUpdates(onUpdateAvailable: (String) -> Unit) {
        Executors.newSingleThreadExecutor().execute {
            try {
                val connection = URL(RELEASES_URL).openConnection() as HttpURLConnection
                connection.instanceFollowRedirects = false
                connection.connectTimeout = 10000
                connection.readTimeout = 10000
                connection.setRequestProperty("User-Agent", "WildDetector")
                connection.connect()
                val location = connection.getHeaderField("Location")
                connection.disconnect()

                // Location: https://github.com/WildKernels/Wild_Detector/releases/tag/vN
                val latestCode = location?.substringAfterLast("/v")?.toIntOrNull()
                Log.d(TAG, "update check: location=$location latest=$latestCode installed=${getVersionCode()}")

                if (latestCode == null || latestCode <= getVersionCode()) return@execute

                Handler(Looper.getMainLooper()).post { onUpdateAvailable("v$latestCode") }
            } catch (e: Exception) {
                // silent: this is the automatic background check
                Log.d(TAG, "update check failed", e)
            }
        }
    }

    fun openReleasesPage() {
        context.startActivity(
            Intent(Intent.ACTION_VIEW, Uri.parse(RELEASES_URL))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
    }

    private fun getVersionCode(): Int =
        try {
            context.packageManager.getPackageInfo(context.packageName, 0).let {
                if (android.os.Build.VERSION.SDK_INT >= 28) it.longVersionCode.toInt() else it.versionCode
            }
        } catch (e: PackageManager.NameNotFoundException) {
            0
        }

    companion object {
        private const val TAG = "WildDetector"
        const val RELEASES_URL = "https://github.com/WildKernels/Wild_Detector/releases/latest"
    }
}
