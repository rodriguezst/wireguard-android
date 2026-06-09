/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.tv.autoconnect

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.ForegroundInfo
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.wireguard.android.R
import com.wireguard.android.activity.TvMainActivity
import java.util.concurrent.TimeUnit

class TvAutoConnectWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        Log.i(TAG, "TV auto-connect worker start")
        setForeground(createForegroundInfo())
        return when (val outcome = TvAutoConnect.connectLastUsedIfEnabled(applicationContext, "boot")) {
            is TvAutoConnect.Outcome.Failure -> if (outcome.retry) Result.retry() else Result.success()
            else -> Result.success()
        }
    }

    private fun createForegroundInfo(): ForegroundInfo {
        val notification = createNotification()
        return ForegroundInfo(NOTIFICATION_ID, notification)
    }

    private fun createNotification(): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                applicationContext.getString(R.string.tv_auto_connect_notification_channel),
                NotificationManager.IMPORTANCE_LOW,
            )
            applicationContext.getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }

        val launchIntent = Intent(applicationContext, TvMainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val pendingIntent = PendingIntent.getActivity(
            applicationContext,
            0,
            launchIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            Notification.Builder(applicationContext, NOTIFICATION_CHANNEL_ID)
        else
            @Suppress("DEPRECATION")
            Notification.Builder(applicationContext)

        return builder
            .setContentTitle(applicationContext.getString(R.string.tv_auto_connect_notification_title))
            .setContentText(applicationContext.getString(R.string.tv_auto_connect_notification_text))
            .setContentIntent(pendingIntent)
            .setSmallIcon(R.drawable.ic_tile)
            .setOngoing(true)
            .build()
    }

    companion object {
        fun enqueue(context: Context) {
            val request = OneTimeWorkRequestBuilder<TvAutoConnectWorker>()
                .setInitialDelay(5, TimeUnit.SECONDS)
                .build()
            WorkManager.getInstance(context.applicationContext)
                .enqueueUniqueWork(UNIQUE_WORK_NAME, ExistingWorkPolicy.KEEP, request)
        }

        private const val TAG = "WireGuard/TvAutoConnectWorker"
        private const val NOTIFICATION_CHANNEL_ID = "tv_auto_connect"
        private const val NOTIFICATION_ID = 8801
        private const val UNIQUE_WORK_NAME = "tv_auto_connect_on_boot"
    }
}
