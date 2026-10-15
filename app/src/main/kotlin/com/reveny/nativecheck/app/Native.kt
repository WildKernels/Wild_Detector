package com.reveny.nativecheck.app

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.widget.Toast

class Native {
    companion object {
        init {
            System.loadLibrary("wild")
        }
    }

    external fun getDetections(context: Context, pm: PackageManager, enableExperimental: Boolean): Array<DetectionData>
}