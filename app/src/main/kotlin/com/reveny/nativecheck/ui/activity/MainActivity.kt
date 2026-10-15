package com.reveny.nativecheck.ui.activity

import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import com.reveny.nativecheck.R
import com.reveny.nativecheck.app.UpdateChecker
import com.reveny.nativecheck.repository.AppSettingsRepository
import com.reveny.nativecheck.ui.providable.LocalAppSettings
import com.reveny.nativecheck.ui.theme.AppTheme
import com.reveny.nativecheck.viewmodel.MainViewModel
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : AppCompatActivity() {
    @Inject
    lateinit var appSettingsRepository: AppSettingsRepository

    private val mainViewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            window.isNavigationBarContrastEnforced = false
        }

        mainViewModel.initializeData(this)

        val packageManager = packageManager

        // Use a coroutine to retrieve the value from preferences
        lifecycleScope.launch {
            val enableExperimental = appSettingsRepository.data.first().enableExperimentalDetections
            mainViewModel.performTask(this@MainActivity, packageManager, enableExperimental)
        }

        val updateChecker = UpdateChecker(this)

        setContent {
            val userPreferences by appSettingsRepository.data.collectAsStateWithLifecycle(
                initialValue = null,
                lifecycle = lifecycle
            )

            userPreferences ?: return@setContent

            CompositionLocalProvider(LocalAppSettings provides userPreferences!!) {
                AppTheme {
                    MainScreen(mainViewModel)
                    UpdateCheck(updateChecker)
                }
            }
        }
    }

    fun showToast(text: String) {
        this.runOnUiThread {
            Toast.makeText(this, text, Toast.LENGTH_LONG).show()
        }
    }

    @Composable
    fun UpdateCheck(updateChecker: UpdateChecker) {
        var showDialog by remember { mutableStateOf(false) }
        var latestVersion by remember { mutableStateOf("") }

        if (showDialog) {
            UpdateDialog(
                latestVersion = latestVersion,
                onConfirm = {
                    showDialog = false
                    updateChecker.openReleasesPage()
                },
                onCancel = { showDialog = false }
            )
        }

        LaunchedEffect(Unit) {
            updateChecker.checkForUpdates { version ->
                latestVersion = version
                showDialog = true
            }
        }
    }
}

@Composable
fun UpdateDialog(
    latestVersion: String,
    onConfirm: () -> Unit,
    onCancel: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text(text = stringResource(R.string.update_available)) },
        text = {
            Text(
                text = String.format(
                    stringResource(R.string.version_is_available),
                    latestVersion
                )
            )
        },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(stringResource(R.string.update_open))
            }
        },
        dismissButton = {
            TextButton(onClick = onCancel) {
                Text(stringResource(R.string.update_cancel))
            }
        },
        modifier = Modifier.padding(16.dp)
    )
}