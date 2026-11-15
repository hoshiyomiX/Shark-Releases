package com.shark.kty

import android.content.Context
import android.content.pm.PackageManager
import android.os.ParcelFileDescriptor
import moe.shizuku.server.IShizukuService
import rikka.shizuku.Shizuku
import roro.stellar.Stellar
import roro.stellar.StellarHelper
import java.io.File
import java.io.InputStream
import java.io.OutputStream

enum class PrivBackend(val label: String) {
    STELLAR("Stellar"),
    SHIZUKU("Shizuku"),
    /**
     * App-direct execution (ghostlock-app model): the CVE-2026-43499 engine
     * is spawned with a plain ProcessBuilder inside the app sandbox
     * (untrusted_app domain) - no Stellar / Shizuku / ADB involved. Only the
     * kernels with a bundled GLK1 profile (and the libghostlock.so engine)
     * support it; see MainActivity.appDirectAvailable().
     */
    LOCAL("App-direct")
}

class PrivProcess(
    private val inS: InputStream,
    private val outS: OutputStream,
    private val errS: InputStream,
    private val waiter: () -> Int
) {
    fun getInputStream(): InputStream = inS
    fun getOutputStream(): OutputStream = outS
    fun getErrorStream(): InputStream = errS
    fun waitFor(): Int = waiter()
}

object PrivService {
    fun pick(): PrivBackend? = when {
        runCatching { Stellar.pingBinder() }.getOrDefault(false) -> PrivBackend.STELLAR
        runCatching { Shizuku.pingBinder() }.getOrDefault(false) -> PrivBackend.SHIZUKU
        else -> null
    }

    /** Same as pick() but falls back to the local app-direct backend when the
     * caller has verified this kernel supports it. Order stays
     * Stellar > Shizuku > LOCAL: the shell backends run every runner, LOCAL
     * only runs the app-domain 43499 engine. */
    fun pickOrLocal(appDirectSupported: Boolean): PrivBackend? =
        pick() ?: if (appDirectSupported) PrivBackend.LOCAL else null

    fun granted(): Boolean = grantedFor(pick())

    fun grantedFor(backend: PrivBackend?): Boolean = when (backend) {
        PrivBackend.LOCAL -> true
        PrivBackend.STELLAR -> runCatching { Stellar.checkSelfPermission("stellar") }.getOrDefault(false)
        PrivBackend.SHIZUKU -> runCatching {
            Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
        }.getOrDefault(false)
        null -> false
    }

    fun request(code: Int) {
        when (pick()) {
            PrivBackend.STELLAR -> Stellar.requestPermission("stellar", code)
            PrivBackend.SHIZUKU -> Shizuku.requestPermission(code)
            PrivBackend.LOCAL -> Unit // app-direct needs no permission grant
            null -> Unit
        }
    }

    fun newProcess(cmd: Array<String>, env: Array<String>?, dir: String?): PrivProcess =
        newProcessFor(pick() ?: PrivBackend.LOCAL, cmd, env, dir)

    fun newProcessFor(backend: PrivBackend, cmd: Array<String>, env: Array<String>?, dir: String?): PrivProcess =
        when (backend) {
            PrivBackend.STELLAR -> {
                @Suppress("UNCHECKED_CAST")
                val p = Stellar.newProcess(cmd as Array<String?>, env as Array<String?>?, dir)
                PrivProcess(p.getInputStream(), p.getOutputStream(), p.getErrorStream()) { p.waitFor() }
            }
            PrivBackend.SHIZUKU -> {
                val binder = Shizuku.getBinder() ?: error("Shizuku binder null")
                val svc = IShizukuService.Stub.asInterface(binder) ?: error("Shizuku service null")
                val p = svc.newProcess(cmd, env, dir)
                PrivProcess(
                    ParcelFileDescriptor.AutoCloseInputStream(p.getInputStream()),
                    ParcelFileDescriptor.AutoCloseOutputStream(p.getOutputStream()),
                    ParcelFileDescriptor.AutoCloseInputStream(p.getErrorStream())
                ) { p.waitFor() }
            }
            PrivBackend.LOCAL -> newLocalProcess(cmd, env, dir)
        }

    /** Plain ProcessBuilder spawn inside the app sandbox. The engine binary
     * lives in nativeLibraryDir (the only app-owned exec path), exactly the
     * ghostlock-app execution model. */
    private fun newLocalProcess(cmd: Array<String>, env: Array<String>?, dir: String?): PrivProcess {
        val pb = ProcessBuilder(*cmd).redirectErrorStream(false)
        dir?.let { pb.directory(File(it)) }
        val envMap = pb.environment()
        // keep the inherited environment (PATH etc.) and apply overrides
        env?.forEach { line ->
            val eq = line.indexOf('=')
            if (eq > 0) envMap[line.substring(0, eq)] = line.substring(eq + 1)
        }
        val p = pb.start()
        return PrivProcess(
            p.inputStream,
            p.outputStream,
            p.errorStream
        ) { p.waitFor() }
    }

    fun openManager(context: Context) {
        if (runCatching { StellarHelper.openManager(context) }.getOrDefault(false)) return
        val intent = context.packageManager.getLaunchIntentForPackage("moe.shizuku.privileged.api")
            ?.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
        if (intent != null) {
            runCatching { context.startActivity(intent) }
        }
    }
}
