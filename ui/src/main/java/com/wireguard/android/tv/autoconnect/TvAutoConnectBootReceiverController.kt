/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.tv.autoconnect

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DISABLED
import android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_ENABLED
import android.content.pm.PackageManager.DONT_KILL_APP
import com.wireguard.android.util.UserKnobs
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach

object TvAutoConnectBootReceiverController {
    fun setEnabled(context: Context, enabled: Boolean) {
        val receiverName = ComponentName(context.applicationContext, TvAutoConnectBootReceiver::class.java)
        val newState = if (enabled) COMPONENT_ENABLED_STATE_ENABLED else COMPONENT_ENABLED_STATE_DISABLED
        context.applicationContext.packageManager.setComponentEnabledSetting(receiverName, newState, DONT_KILL_APP)
    }

    fun start(context: Context, scope: CoroutineScope) {
        UserKnobs.tvAutoConnectOnBoot
            .onEach { setEnabled(context, it) }
            .launchIn(scope)
    }
}
