package com.reveny.nativecheck.ui.component

import android.annotation.SuppressLint
import android.content.Intent
import androidx.appcompat.app.AppCompatDelegate
import androidx.compose.foundation.layout.Box
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.core.os.LocaleListCompat
import androidx.hilt.navigation.compose.hiltViewModel
import com.reveny.nativecheck.R
import com.reveny.nativecheck.datastore.model.Language as LanguagePref
import com.reveny.nativecheck.viewmodel.SettingsViewModel
import compose.icons.TablerIcons
import compose.icons.tablericons.outline.Language
import java.util.Locale

private val LanguageItems = LanguageEntry.entries.toTypedArray()

/** Top-bar language picker (moved here from the removed Settings screen). */
@Composable
fun LanguageMenu() {
    var expanded by remember { mutableStateOf(false) }
    val context = LocalContext.current
    val settingsViewModel: SettingsViewModel = hiltViewModel()

    Box {
        IconButton(onClick = { expanded = true }) {
            Icon(
                TablerIcons.Outline.Language,
                contentDescription = stringResource(R.string.pref_language)
            )
        }
        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            LanguageItems.forEach { item ->
                DropdownMenuItem(
                    text = { Text(stringResource(item.text)) },
                    onClick = {
                        settingsViewModel.setLanguage(item.value)
                        AppCompatDelegate.setApplicationLocales(LocaleListCompat.create(item.locale))
                        expanded = false

                        // Restart the activity to apply the new language
                        val intent = context.packageManager.getLaunchIntentForPackage(context.packageName)
                        intent?.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP)
                        context.startActivity(intent)
                    }
                )
            }
        }
    }
}

private enum class LanguageEntry(
    val value: LanguagePref,
    val locale: Locale?,
    val text: Int,
) {
    @SuppressLint("ConstantLocale")
    ENGLISH(LanguagePref.ENGLISH, Locale("en"), R.string.en),
    ARABIC(LanguagePref.ARABIC, Locale("ar"), R.string.ar),
    GERMAN(LanguagePref.GERMAN, Locale("de"), R.string.de),
    GREEK(LanguagePref.GREEK, Locale("el"), R.string.el),
    SPANISH(LanguagePref.SPANISH, Locale("es"), R.string.es),
    INDONESIAN(LanguagePref.INDONESIAN, Locale("id"), R.string.id),
    JAPANESE(LanguagePref.JAPANESE, Locale("ja"), R.string.ja),
    POLISH(LanguagePref.POLISH, Locale("pl"), R.string.pl),
    PORTUGUESE_BRAZIL(LanguagePref.PORTUGUESE_BRAZIL, Locale("pt", "BR"), R.string.pt_br),
    RUSSIAN(LanguagePref.RUSSIAN, Locale("ru"), R.string.ru),
    SLOVENIAN(LanguagePref.SLOVENIAN, Locale("sl"), R.string.sl),
    TURKISH_TURKEY(LanguagePref.TURKISH_TURKEY, Locale("tr", "TR"), R.string.tr_tr),
    VIETNAMESE(LanguagePref.VIETNAMESE, Locale("vi"), R.string.vi),
    CHINESE_SIMPLIFIED(LanguagePref.CHINESE_SIMPLIFIED, Locale("zh", "CN"), R.string.zh_cn),
    CHINESE_TRADITIONAL(LanguagePref.CHINESE_TRADITIONAL, Locale("zh", "TW"), R.string.zh_tw),
    BULGARIAN(LanguagePref.BULGARIAN, Locale("bg"), R.string.bg)
}
