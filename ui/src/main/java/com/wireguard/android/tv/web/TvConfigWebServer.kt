/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.tv.web

import android.Manifest
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PackageManager.PackageInfoFlags
import android.os.Build
import android.util.Base64
import android.util.Log
import com.wireguard.android.Application
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import com.wireguard.crypto.KeyPair
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.BufferedWriter
import java.io.InputStream
import java.io.OutputStreamWriter
import java.math.BigInteger
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.KeyPair as JavaKeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import java.util.Locale
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLServerSocket
import kotlin.math.max

class TvConfigWebServer(private val context: Context) {
    data class Session(val url: String, val pin: String, val certificateFingerprint: String)

    @Volatile
    private var serverSocket: ServerSocket? = null
    @Volatile
    private var running = false
    @Volatile
    private var token = ""
    @Volatile
    private var lastActivityMs = 0L
    private var failedAuthAttempts = 0
    private var executor: ExecutorService? = null
    private var session: Session? = null

    val isRunning: Boolean
        get() = running

    @Synchronized
    fun start(): Session {
        session?.let {
            if (running)
                return it
        }
        val bindAddress = findLanAddress() ?: InetAddress.getByName("127.0.0.1")
        val tlsServerSocket = createTlsServerSocket(bindAddress)
        val socket = tlsServerSocket.socket
        socket.soTimeout = ACCEPT_TIMEOUT_MS.toInt()
        serverSocket = socket
        running = true
        failedAuthAttempts = 0
        token = randomToken()
        lastActivityMs = System.currentTimeMillis()
        val newSession = Session("https://${bindAddress.hostAddress}:${socket.localPort}/", randomPin(), tlsServerSocket.certificateFingerprint)
        session = newSession
        executor = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "TvConfigWebServer").apply { isDaemon = true }
        }.also { it.execute { acceptLoop(newSession.pin) } }
        Log.i(TAG, "TV config web server started at ${newSession.url}")
        return newSession
    }

    @Synchronized
    fun stop() {
        if (!running)
            return
        running = false
        try {
            serverSocket?.close()
        } catch (_: Throwable) {
        }
        serverSocket = null
        session = null
        token = ""
        executor?.shutdownNow()
        executor = null
        Log.i(TAG, "TV config web server stopped")
    }

    private fun acceptLoop(pin: String) {
        try {
            while (running) {
                if (System.currentTimeMillis() - lastActivityMs > INACTIVITY_TIMEOUT_MS) {
                    Log.i(TAG, "TV config web server stopping after inactivity")
                    stop()
                    return
                }
                val socket = try {
                    serverSocket?.accept() ?: return
                } catch (_: SocketTimeoutException) {
                    continue
                } catch (_: SocketException) {
                    return
                }
                try {
                    socket.use { handleClient(it, pin) }
                } catch (e: SSLException) {
                    if (running)
                        Log.i(TAG, "TV config web server TLS connection failed: ${e.message}")
                } catch (e: SocketTimeoutException) {
                    if (running)
                        Log.i(TAG, "TV config web server client request timed out")
                } catch (e: SocketException) {
                    if (running)
                        Log.i(TAG, "TV config web server client connection closed: ${e.message}")
                } catch (e: Throwable) {
                    if (running)
                        Log.e(TAG, "TV config web server client request failed", e)
                }
            }
        } catch (e: Throwable) {
            if (running)
                Log.e(TAG, "TV config web server failed", e)
        } finally {
            if (running)
                stop()
        }
    }

    private fun handleClient(socket: Socket, pin: String) {
        socket.soTimeout = REQUEST_TIMEOUT_MS.toInt()
        val request = readRequest(socket) ?: return
        lastActivityMs = System.currentTimeMillis()
        var stopAfterResponse = false
        val response = try {
            when {
                request.method == "GET" && request.path == "/" -> assetResponse()
                request.path.startsWith("/api/") && request.path != "/api/auth" && !isAuthorized(request) -> jsonResponse(401, JSONObject().put("error", "Unauthorized"))
                request.method == "POST" && request.path == "/api/auth" -> {
                    val body = JSONObject(request.body.ifBlank { "{}" })
                    if (body.optString("pin") == pin) {
                        failedAuthAttempts = 0
                        jsonResponse(200, JSONObject().put("token", token))
                    } else {
                        failedAuthAttempts++
                        if (failedAuthAttempts >= MAX_AUTH_FAILURES)
                            stopAfterResponse = true
                        jsonResponse(403, JSONObject().put("error", "Invalid PIN"))
                    }
                }
                request.method == "GET" && request.path == "/api/apps" -> jsonResponse(200, listApps())
                request.method == "GET" && request.path == "/api/tunnels" -> jsonResponse(200, listTunnels())
                request.method == "POST" && request.path == "/api/tunnels" -> createTunnel(request.body)
                request.method == "GET" && request.path.startsWith("/api/tunnels/") -> tunnelConfigResponse(request.path.removePrefix("/api/tunnels/"))
                request.method == "PUT" && request.path.startsWith("/api/tunnels/") -> updateTunnel(request.path.removePrefix("/api/tunnels/"), request.body)
                request.method == "DELETE" && request.path.startsWith("/api/tunnels/") -> deleteTunnel(request.path.removePrefix("/api/tunnels/"))
                request.method == "GET" && request.path == "/api/keypair" -> keyPairResponse()
                else -> jsonResponse(404, JSONObject().put("error", "Not found"))
            }
        } catch (e: Throwable) {
            Log.e(TAG, "TV config web server request failed", e)
            jsonResponse(500, JSONObject().put("error", "Internal server error"))
        }
        writeResponse(socket, response)
        if (stopAfterResponse) {
            Log.i(TAG, "TV config web server stopping after repeated authentication failures")
            stop()
        }
    }

    private fun readRequest(socket: Socket): Request? {
        val input = socket.getInputStream()
        val requestLine = readHeaderLine(input) ?: return null
        val parts = requestLine.split(' ')
        if (parts.size < 2)
            return null
        val headers = mutableMapOf<String, String>()
        while (true) {
            val line = readHeaderLine(input) ?: return null
            if (line.isEmpty())
                break
            val separator = line.indexOf(':')
            if (separator <= 0)
                continue
            headers[line.substring(0, separator).lowercase(Locale.ROOT)] = line.substring(separator + 1).trim()
        }
        val contentLength = max(0, headers["content-length"]?.toIntOrNull() ?: 0)
        val body = if (contentLength > 0) {
            val bytes = ByteArray(contentLength)
            var read = 0
            while (read < contentLength) {
                val count = input.read(bytes, read, contentLength - read)
                if (count < 0)
                    return null
                read += count
            }
            String(bytes, StandardCharsets.UTF_8)
        } else {
            ""
        }
        val rawPath = parts[1].substringBefore('?')
        return Request(parts[0], rawPath, headers, body)
    }

    private fun readHeaderLine(input: InputStream): String? {
        val bytes = ArrayList<Byte>()
        while (true) {
            val next = input.read()
            if (next < 0)
                return if (bytes.isEmpty()) null else String(bytes.toByteArray(), StandardCharsets.ISO_8859_1)
            if (next == '\n'.code)
                return String(bytes.toByteArray(), StandardCharsets.ISO_8859_1)
            if (next != '\r'.code)
                bytes.add(next.toByte())
        }
    }

    private fun writeResponse(socket: Socket, response: Response) {
        val writer = BufferedWriter(OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8))
        writer.write("HTTP/1.1 ${response.status} ${reason(response.status)}\r\n")
        writer.write("Content-Type: ${response.contentType}\r\n")
        writer.write("Content-Length: ${response.body.size}\r\n")
        writer.write("Cache-Control: no-store\r\n")
        writer.write("Connection: close\r\n")
        writer.write("\r\n")
        writer.flush()
        socket.getOutputStream().write(response.body)
        socket.getOutputStream().flush()
    }

    private fun assetResponse(): Response {
        val bytes = context.assets.open("tv-web/index.html").use { it.readBytes() }
        return Response(200, "text/html; charset=utf-8", bytes)
    }

    private fun isAuthorized(request: Request): Boolean =
        request.headers["authorization"] == "Bearer $token"

    private fun listApps(): JSONArray {
        val packageManager = context.packageManager
        val apps = getPackagesHoldingPermissions(packageManager, arrayOf(Manifest.permission.INTERNET))
            .mapNotNull { packageInfo ->
                val packageName = packageInfo.packageName ?: return@mapNotNull null
                val appInfo = packageInfo.applicationInfo ?: return@mapNotNull null
                val label = appInfo.loadLabel(packageManager)?.toString()?.ifBlank { packageName } ?: packageName
                AppEntry(label, packageName)
            }
            .sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER, AppEntry::name).thenBy(AppEntry::packageName))
        return JSONArray().also { array ->
            apps.forEach { app ->
                array.put(JSONObject().put("name", app.name).put("packageName", app.packageName))
            }
        }
    }

    private fun getPackagesHoldingPermissions(packageManager: PackageManager, permissions: Array<String>): List<PackageInfo> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getPackagesHoldingPermissions(permissions, PackageInfoFlags.of(0L))
        } else {
            @Suppress("DEPRECATION")
            packageManager.getPackagesHoldingPermissions(permissions, 0)
        }

    private fun listTunnels(): JSONArray = runBlocking {
        val tunnels = Application.getTunnelManager().getTunnels()
        JSONArray().also { array ->
            tunnels.forEach { tunnel ->
                array.put(JSONObject().put("name", tunnel.name).put("state", tunnel.state.name))
            }
        }
    }

    private fun tunnelConfigResponse(encodedName: String): Response = runBlocking {
        val name = URLDecoder.decode(encodedName, StandardCharsets.UTF_8.name())
        val tunnel = Application.getTunnelManager().getTunnels()[name]
            ?: return@runBlocking jsonResponse(404, JSONObject().put("error", "Tunnel not found"))
        val config = tunnel.getConfigAsync().toWgQuickString()
        Response(200, "text/plain; charset=utf-8", config.toByteArray(StandardCharsets.UTF_8))
    }

    private fun createTunnel(bodyText: String): Response = runBlocking {
        val body = try {
            JSONObject(bodyText.ifBlank { "{}" })
        } catch (_: Throwable) {
            return@runBlocking jsonResponse(400, JSONObject().put("error", "Invalid request body"))
        }
        val name = body.optString("name").trim()
        val configText = body.optString("configText")
        if (name.isEmpty() || configText.isBlank())
            return@runBlocking jsonResponse(400, JSONObject().put("error", "Name and config are required"))
        val config = parseConfig(configText)
            ?: return@runBlocking jsonResponse(400, JSONObject().put("error", "Invalid WireGuard config"))
        try {
            Application.getTunnelManager().create(name, config)
            jsonResponse(200, JSONObject().put("name", name))
        } catch (e: IllegalArgumentException) {
            jsonResponse(400, JSONObject().put("error", e.message ?: "Invalid tunnel"))
        } catch (e: Throwable) {
            Log.e(TAG, "TV config web server create failed", e)
            jsonResponse(500, JSONObject().put("error", "Unable to create tunnel"))
        }
    }

    private fun updateTunnel(encodedName: String, bodyText: String): Response = runBlocking {
        val name = URLDecoder.decode(encodedName, StandardCharsets.UTF_8.name())
        val tunnel = Application.getTunnelManager().getTunnels()[name]
            ?: return@runBlocking jsonResponse(404, JSONObject().put("error", "Tunnel not found"))
        if (tunnel.state == Tunnel.State.UP)
            return@runBlocking jsonResponse(409, JSONObject().put("error", "Stop the tunnel before editing it"))
        val body = try {
            JSONObject(bodyText.ifBlank { "{}" })
        } catch (_: Throwable) {
            return@runBlocking jsonResponse(400, JSONObject().put("error", "Invalid request body"))
        }
        val configText = body.optString("configText")
        if (configText.isBlank())
            return@runBlocking jsonResponse(400, JSONObject().put("error", "Config is required"))
        val config = parseConfig(configText)
            ?: return@runBlocking jsonResponse(400, JSONObject().put("error", "Invalid WireGuard config"))
        try {
            tunnel.setConfigAsync(config)
            jsonResponse(200, JSONObject().put("name", name))
        } catch (e: Throwable) {
            Log.e(TAG, "TV config web server update failed", e)
            jsonResponse(500, JSONObject().put("error", "Unable to update tunnel"))
        }
    }

    private fun deleteTunnel(encodedName: String): Response = runBlocking {
        val name = URLDecoder.decode(encodedName, StandardCharsets.UTF_8.name())
        val tunnel = Application.getTunnelManager().getTunnels()[name]
            ?: return@runBlocking jsonResponse(404, JSONObject().put("error", "Tunnel not found"))
        if (tunnel.state == Tunnel.State.UP)
            return@runBlocking jsonResponse(409, JSONObject().put("error", "Stop the tunnel before deleting it"))
        try {
            tunnel.deleteAsync()
            jsonResponse(200, JSONObject().put("name", name))
        } catch (e: Throwable) {
            Log.e(TAG, "TV config web server delete failed", e)
            jsonResponse(500, JSONObject().put("error", "Unable to delete tunnel"))
        }
    }

    private fun keyPairResponse(): Response {
        val keyPair = KeyPair()
        return jsonResponse(
            200,
            JSONObject()
                .put("privateKey", keyPair.privateKey.toBase64())
                .put("publicKey", keyPair.publicKey.toBase64()),
        )
    }

    private fun parseConfig(configText: String): Config? =
        try {
            Config.parse(ByteArrayInputStream(configText.toByteArray(StandardCharsets.UTF_8)))
        } catch (_: Throwable) {
            null
        }

    private fun jsonResponse(status: Int, body: JSONObject): Response =
        Response(status, "application/json; charset=utf-8", body.toString().toByteArray(StandardCharsets.UTF_8))

    private fun jsonResponse(status: Int, body: JSONArray): Response =
        Response(status, "application/json; charset=utf-8", body.toString().toByteArray(StandardCharsets.UTF_8))

    private fun randomPin(): String = String.format(Locale.US, "%08d", secureRandom.nextInt(100_000_000))

    private fun randomToken(): String {
        val bytes = ByteArray(32)
        secureRandom.nextBytes(bytes)
        return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    private fun createTlsServerSocket(bindAddress: InetAddress): TlsServerSocket {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"), secureRandom)
        }
        val keyPair = keyPairGenerator.generateKeyPair()
        val certificate = generateSelfSignedCertificate(bindAddress, keyPair)
        val password = randomToken().toCharArray()
        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setKeyEntry(TLS_KEY_ALIAS, keyPair.private, password, arrayOf(certificate))
        }
        val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
            init(keyStore, password)
        }
        val sslContext = SSLContext.getInstance("TLS").apply {
            init(keyManagerFactory.keyManagers, null, secureRandom)
        }
        val socket = sslContext.serverSocketFactory.createServerSocket(0, 50, bindAddress) as SSLServerSocket
        val enabledProtocols = socket.supportedProtocols
            .filter { it == "TLSv1.3" || it == "TLSv1.2" }
            .toTypedArray()
        if (enabledProtocols.isNotEmpty())
            socket.enabledProtocols = enabledProtocols
        return TlsServerSocket(socket, certificateFingerprint(certificate))
    }

    private fun generateSelfSignedCertificate(bindAddress: InetAddress, keyPair: JavaKeyPair): X509Certificate {
        val now = System.currentTimeMillis()
        val subject = X500Name("CN=${bindAddress.hostAddress}")
        val serial = BigInteger(160, secureRandom).let { if (it.signum() > 0) it else BigInteger.ONE }
        val builder = JcaX509v3CertificateBuilder(
            subject,
            serial,
            Date(now - CERTIFICATE_CLOCK_SKEW_MS),
            Date(now + CERTIFICATE_VALIDITY_MS),
            subject,
            keyPair.public,
        )
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
        builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature))
        builder.addExtension(Extension.extendedKeyUsage, false, ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth))
        builder.addExtension(
            Extension.subjectAlternativeName,
            false,
            GeneralNames(GeneralName(GeneralName.iPAddress, bindAddress.hostAddress)),
        )
        val signer = JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.private)
        return JcaX509CertificateConverter().getCertificate(builder.build(signer)).apply {
            verify(keyPair.public)
        }
    }

    private fun certificateFingerprint(certificate: X509Certificate): String =
        MessageDigest.getInstance("SHA-256")
            .digest(certificate.encoded)
            .joinToString(":") { String.format(Locale.US, "%02X", it.toInt() and 0xff) }

    private fun findLanAddress(): InetAddress? {
        val interfaces = NetworkInterface.getNetworkInterfaces() ?: return null
        for (networkInterface in interfaces) {
            if (!networkInterface.isUp || networkInterface.isLoopback)
                continue
            val addresses = networkInterface.inetAddresses
            for (address in addresses) {
                if (address is Inet4Address && !address.isLoopbackAddress && address.isSiteLocalAddress)
                    return address
            }
        }
        return null
    }

    private fun reason(status: Int): String = when (status) {
        200 -> "OK"
        401 -> "Unauthorized"
        403 -> "Forbidden"
        404 -> "Not Found"
        409 -> "Conflict"
        500 -> "Internal Server Error"
        else -> "OK"
    }

    private data class Request(val method: String, val path: String, val headers: Map<String, String>, val body: String)
    private data class Response(val status: Int, val contentType: String, val body: ByteArray)
    private data class TlsServerSocket(val socket: SSLServerSocket, val certificateFingerprint: String)
    private data class AppEntry(val name: String, val packageName: String)

    companion object {
        private const val TAG = "WireGuard/TvConfigWebServer"
        private const val ACCEPT_TIMEOUT_MS = 2_000L
        private const val REQUEST_TIMEOUT_MS = 5_000L
        private const val INACTIVITY_TIMEOUT_MS = 10 * 60 * 1000L
        private const val MAX_AUTH_FAILURES = 5
        private const val CERTIFICATE_CLOCK_SKEW_MS = 60 * 60 * 1000L
        private const val CERTIFICATE_VALIDITY_MS = 7 * 24 * 60 * 60 * 1000L
        private const val TLS_KEY_ALIAS = "tv-config-web-server"
        private val secureRandom = SecureRandom()
    }
}
