/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.tv.autoconnect

import android.content.Context
import android.util.Log
import com.wireguard.android.Application
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.android.util.UserKnobs
import kotlinx.coroutines.flow.first

object TvAutoConnect {
    sealed class Outcome {
        data object Disabled : Outcome()
        data object NoLastUsedTunnel : Outcome()
        data object TunnelNotFound : Outcome()
        data object NoVpnPermission : Outcome()
        data object AlreadyUp : Outcome()
        data object Connected : Outcome()
        data class Failure(val retry: Boolean, val throwable: Throwable) : Outcome()
    }

    suspend fun connectLastUsedIfEnabled(context: Context, reason: String): Outcome {
        if (!UserKnobs.tvAutoConnectOnBoot.first()) {
            Log.i(TAG, "Skipping TV auto-connect for $reason: disabled")
            return Outcome.Disabled
        }

        val tunnelManager = Application.getTunnelManager()
        val tunnels = try {
            tunnelManager.getTunnels()
        } catch (e: Throwable) {
            Log.e(TAG, "TV auto-connect failed waiting for tunnels during $reason", e)
            return Outcome.Failure(retry = true, throwable = e)
        }

        val lastUsedTunnel = tunnelManager.lastUsedTunnel ?: run {
            Log.i(TAG, "Skipping TV auto-connect for $reason: no last-used tunnel")
            return Outcome.NoLastUsedTunnel
        }
        val tunnel = tunnels[lastUsedTunnel.name] ?: run {
            Log.i(TAG, "Skipping TV auto-connect for $reason: last-used tunnel no longer exists")
            return Outcome.TunnelNotFound
        }

        val backend = try {
            Application.getBackend()
        } catch (e: Throwable) {
            Log.e(TAG, "TV auto-connect failed waiting for backend during $reason", e)
            return Outcome.Failure(retry = true, throwable = e)
        }

        if (backend is GoBackend && GoBackend.VpnService.prepare(context.applicationContext) != null) {
            Log.i(TAG, "Skipping TV auto-connect for $reason: VPN permission is not granted")
            return Outcome.NoVpnPermission
        }
        if (tunnel.state == Tunnel.State.UP) {
            Log.i(TAG, "Skipping TV auto-connect for $reason: tunnel is already up")
            return Outcome.AlreadyUp
        }

        return try {
            tunnelManager.setTunnelState(tunnel, Tunnel.State.UP)
            Log.i(TAG, "TV auto-connect brought up ${tunnel.name} for $reason")
            Outcome.Connected
        } catch (e: Throwable) {
            Log.e(TAG, "TV auto-connect failed bringing up ${tunnel.name} during $reason", e)
            Outcome.Failure(retry = false, throwable = e)
        }
    }

    private const val TAG = "WireGuard/TvAutoConnect"
}
