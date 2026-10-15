package com.reveny.nativecheck.app
import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.widget.Toast
import androidx.core.content.FileProvider
import com.reveny.nativecheck.R
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors

/** Update checks run against this repo's GitHub releases; the upstream
 * dl.reveny.me endpoint was removed.
 *
 * Instead of the rate-limited api.github.com JSON endpoint we resolve
 * https://github.com/TheWildJames/Wild_Detector/releases/latest, which
 * 302-redirects to /releases/tag/vN - one unauthenticated request, no rate
 * limit, no JSON. The automatic launch check stays silent on failure (no
 * error toasts when offline); the download + install flow is unchanged. */
class UpdateChecker(private val context: Context) {
    private val releasesLatestUrl = "https://github.com/TheWildJames/Wild_Detector/releases/latest"
    private val releaseDownloadUrl = "https://github.com/TheWildJames/Wild_Detector/releases/download"

    fun checkForUpdates(onUpdateAvailable: (String, String, String) -> Unit) {
        Executors.newSingleThreadExecutor().execute {
            try {
                val connection = URL(releasesLatestUrl).openConnection() as HttpURLConnection
                connection.instanceFollowRedirects = false
                connection.connectTimeout = 10000
                connection.readTimeout = 10000
                connection.setRequestProperty("User-Agent", "WildDetector")
                connection.connect()
                val location = connection.getHeaderField("Location")
                connection.disconnect()

                // Location: .../releases/tag/vN
                val latest = location?.substringAfterLast("/v")?.toIntOrNull() ?: return@execute
                val current = getCurrentVersion()?.toIntOrNull() ?: return@execute

                if (latest > current) {
                    Handler(Looper.getMainLooper()).post {
                        onUpdateAvailable(
                            latest.toString(),
                            "$releaseDownloadUrl/v$latest/WildDetector-v$latest.apk",
                            "WildDetector-v$latest.apk"
                        )
                    }
                }
            } catch (e: Exception) {
                // silent: this is the automatic background check
                e.printStackTrace()
            }
        }
    }

    private fun getCurrentVersion(): String? {
        return try {
            context.packageManager.getPackageInfo(context.packageName, 0).versionName
        } catch (e: PackageManager.NameNotFoundException) {
            e.printStackTrace()
            null
        }
    }

    @SuppressLint("StringFormatInvalid")
    fun downloadAndInstallApk(apkUrl: String, apkName: String, onProgressUpdate: (Int) -> Unit, onDownloadComplete: (File) -> Unit, onError: (String) -> Unit) {
        val apkFile = File(context.cacheDir, apkName)

        if (apkFile.exists()) {
            onDownloadComplete(apkFile)
            return
        }

        Executors.newSingleThreadExecutor().execute {
            try {
                val url = URL(apkUrl)
                val connection = url.openConnection() as HttpURLConnection
                connection.requestMethod = "GET"
                connection.connect()
                val handler = Handler(Looper.getMainLooper())

                if (connection.responseCode == HttpURLConnection.HTTP_OK) {
                    val fileLength = connection.contentLength
                    val inputStream: InputStream = connection.inputStream
                    val outputStream = FileOutputStream(apkFile)
                    val buffer = ByteArray(1024)
                    var bytesRead: Int
                    var totalBytesRead: Long = 0

                    while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                        outputStream.write(buffer, 0, bytesRead)
                        totalBytesRead += bytesRead
                        val progress = if (fileLength > 0) (totalBytesRead * 100 / fileLength).toInt() else 0
                        handler.post { onProgressUpdate(progress) }
                    }

                    outputStream.close()
                    inputStream.close()
                    connection.disconnect()

                    handler.post { onDownloadComplete(apkFile) }
                } else {
                    handler.post {
                        onError(String.format(context.getString(R.string.download_failed), connection.responseMessage))
                    }
                }
            } catch (e: Exception) {
                e.printStackTrace()
                Handler(Looper.getMainLooper()).post {
                    onError(String.format(context.getString(R.string.error), e.message))
                }
            }
        }
    }

    fun installApk(apkFile: File) {
        val apkUri: Uri = FileProvider.getUriForFile(context, "${context.packageName}.provider", apkFile)
        val canInstall = context.packageManager.canRequestPackageInstalls()

        if (!canInstall) {
            val settingsIntent = Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES).setData(Uri.parse("package:${context.packageName}"))
            context.startActivity(settingsIntent)
            return
        }

        val installIntent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(apkUri, "application/vnd.android.package-archive")
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }

        if (installIntent.resolveActivity(context.packageManager) != null) {
            context.startActivity(installIntent)
        } else {
            Toast.makeText(context, context.getString(R.string.unable_to_install), Toast.LENGTH_LONG).show()
        }
    }
}
