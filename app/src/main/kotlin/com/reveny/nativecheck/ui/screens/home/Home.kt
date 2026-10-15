package com.reveny.nativecheck.ui.screens.home

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LargeTopAppBar
import androidx.compose.material3.MaterialTheme.colorScheme
import androidx.compose.material3.MaterialTheme.typography
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavController
import com.reveny.nativecheck.R
import com.reveny.nativecheck.app.DetectionData
import com.reveny.nativecheck.ui.component.AboutCard
import com.reveny.nativecheck.ui.component.AppInfoCard
import com.reveny.nativecheck.ui.component.CheckCard
import com.reveny.nativecheck.ui.component.DetectionCard
import com.reveny.nativecheck.ui.component.InfoCards
import com.reveny.nativecheck.ui.component.LanguageMenu
import com.reveny.nativecheck.ui.component.SystemInfoCard
import com.reveny.nativecheck.ui.providable.LocalAppSettings
import com.reveny.nativecheck.viewmodel.MainViewModel
import com.reveny.nativecheck.viewmodel.SettingsViewModel
import compose.icons.TablerIcons
import compose.icons.tablericons.Outline
import compose.icons.tablericons.outline.Refresh

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun Home(
    navController: NavController,
    viewModel: MainViewModel,
    detections: List<DetectionData>,
    settingsViewModel: SettingsViewModel = hiltViewModel()
) {
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(
        rememberTopAppBarState(),
        canScroll = { true }
    )
    val appSettings = LocalAppSettings.current
    val context = LocalContext.current

    Scaffold(
        modifier = Modifier
            .fillMaxSize()
            .nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            LargeTopAppBar(
                title = { Text(stringResource(R.string.app_name)) },
                scrollBehavior = scrollBehavior,
                actions = {
                    LanguageMenu()
                    IconButton(
                        onClick = {
                            // force a fresh scan with the current settings
                            viewModel.performTask(context, context.packageManager, false, force = true)
                        },
                        modifier = Modifier.padding(end = 4.dp)
                    ) {
                        Icon(
                            TablerIcons.Outline.Refresh,
                            contentDescription = stringResource(R.string.rescan)
                        )
                    }
                }
            )
        },
        contentWindowInsets = WindowInsets(0, 0, 0, 0)
    ) {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(it),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            item {
                CheckCard(
                    isDetected = detections.isNotEmpty(),
                )
            }

            // Adding detection cards
            items(detections) { detection ->
                DetectionCard(detection = detection)
            }

            item {
                InfoCards(viewModel)
            }

            item {
                AboutCard()
            }
        }
    }
}
