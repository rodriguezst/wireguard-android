/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.tv.autoconnect

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class TvAutoConnectBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED)
            return
        Log.i(TAG, "TV auto-connect boot receiver enqueueing worker")
        TvAutoConnectWorker.enqueue(context.applicationContext)
    }

    companion object {
        private const val TAG = "WireGuard/TvAutoConnectBootReceiver"
    }
}
