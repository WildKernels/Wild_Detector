package com.reveny.nativecheck.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import com.reveny.nativecheck.datastore.model.Language
import com.reveny.nativecheck.repository.AppSettingsRepository
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val appSettingsRepository: AppSettingsRepository
) : ViewModel() {
    fun setLanguage(language: Language) {
        viewModelScope.launch {
            appSettingsRepository.setLanguage(language)
        }
    }

    fun setEnableExperimentalDetections(enableExperimentalDetections: Boolean) {
        viewModelScope.launch {
            appSettingsRepository.setEnableExperimentalDetections(enableExperimentalDetections)
        }
    }
}
