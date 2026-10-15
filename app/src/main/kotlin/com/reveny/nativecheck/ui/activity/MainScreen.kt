package com.reveny.nativecheck.ui.activity

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.rememberNavController
import com.reveny.nativecheck.ui.navigation.MainScreen
import com.reveny.nativecheck.ui.navigation.graphs.homeScreen
import com.reveny.nativecheck.viewmodel.MainViewModel

@Composable
fun MainScreen(viewModel: MainViewModel) {
    val navController = rememberNavController()
    val isLoading by viewModel.isLoading.collectAsState()
    val detections by viewModel.detections.collectAsState()

    if (isLoading) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            CircularProgressIndicator(
                color = MaterialTheme.colorScheme.primary
            )
        }
    } else {
        Scaffold(
            contentWindowInsets = WindowInsets.navigationBars
        ) {
            NavHost(
                modifier = Modifier
                    .padding(bottom = it.calculateBottomPadding()),
                navController = navController,
                startDestination = MainScreen.Home.route,
            ) {
                homeScreen(
                    navController = navController,
                    viewModel = viewModel,
                    detections = detections
                )
            }
        }
    }
}
