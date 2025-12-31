package com.example.frida_detection_nodbg_v1_plugin

import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.content.Context
import android.content.pm.PackageManager
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStream
import java.io.File
import java.net.Socket
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.util.*

class FridaDetectionNodbgV1Plugin : FlutterPlugin, MethodChannel.MethodCallHandler {
    private lateinit var channel: MethodChannel
    private lateinit var context: Context

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(binding.binaryMessenger, "frida_detection_nodbg_v1_plugin")
        channel.setMethodCallHandler(this)
        context = binding.applicationContext
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "isFridaDetected" -> {
                Thread {
                    val detectionResult = isFridaPresent()
                    Handler(Looper.getMainLooper()).post {
                        result.success(detectionResult)
                    }
                }.start()
            }
            else -> result.notImplemented()
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    // Utility: Get all installed package names
    private fun getAllInstalledPackages(): Set<String> {
        val packageManager = context.packageManager
        val allPackages = mutableSetOf<String>()

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                val packages = packageManager.getInstalledPackages(
                    PackageManager.PackageInfoFlags.of(0)
                )
                packages.forEach { allPackages.add(it.packageName) }
            } else {
                @Suppress("DEPRECATION")
                val packages = packageManager.getInstalledPackages(0)
                packages.forEach { allPackages.add(it.packageName) }
            }
        } catch (e: Exception) {
            // Silent failure
        }

        return allPackages
    }

    // Main detection entry point
    private fun isFridaPresent(): Boolean {
        return checkFridaFiles() ||
               checkFridaPorts() ||
               checkFridaProcesses() ||
               checkProcMaps() ||
               checkNamedPipes() ||
               checkThreadNames() ||
               checkEnvironmentVars() ||
               checkFridaApps() ||
               checkNativeLibraries() ||
               checkSystemProperties()
    }

    // 1. Check for Frida-related files
    private fun checkFridaFiles(): Boolean {
        val fridaPaths = arrayOf(
            "/data/local/tmp/frida-server",
            "/data/local/tmp/frida",
            "/data/local/tmp/re.frida.server",
            "/data/local/tmp/frida-server-*",
            "/sdcard/frida-server",
            "/system/bin/frida-server",
            "/system/xbin/frida-server",
            "/data/frida-server",
            "/data/local/tmp/libfrida-gadget.so",
            "/sdcard/libfrida-gadget.so",
            "/system/lib/libfrida-gadget.so",
            "/system/lib64/libfrida-gadget.so",
            "/data/local/tmp/frida-agent.js",
            "/data/local/tmp/_frida.so",
            "/data/local/tmp/gadget.config",
            "/dev/frida-server",
            "/proc/frida",
            "/data/app/frida*"
        )

        for (path in fridaPaths) {
            try {
                if (path.contains("*")) {
                    val parentDir = File(path.substringBeforeLast("/"))
                    if (parentDir.exists() && parentDir.isDirectory) {
                        val pattern = path.substringAfterLast("/").replace("*", "")
                        parentDir.listFiles()?.forEach { file ->
                            if (file.name.contains(pattern)) return true
                        }
                    }
                } else {
                    if (File(path).exists()) return true
                }
            } catch (e: Exception) {
                // Continue
            }
        }
        return false
    }

    // 2. Check Frida server ports
    private fun checkFridaPorts(): Boolean {
        val suspiciousPorts = arrayOf(27042, 27043, 27047, 9999, 9998)

        for (port in suspiciousPorts) {
            try {
                val socket = Socket()
                socket.connect(java.net.InetSocketAddress("127.0.0.1", port), 300)
                socket.close()
                return true
            } catch (e: ConnectException) {
            } catch (e: SocketTimeoutException) {
            } catch (e: Exception) {
            }
        }

        // Fallback: netstat
        try {
            val process = Runtime.getRuntime().exec("netstat -an")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                line?.let {
                    for (port in suspiciousPorts) {
                        if (it.contains(":$port")) {
                            reader.close()
                            return true
                        }
                    }
                }
            }
            reader.close()
            process.waitFor()
        } catch (e: Exception) {
        }
        return false
    }

    // 3. Check Frida processes
    private fun checkFridaProcesses(): Boolean {
        val fridaExecutables = arrayOf(
            "frida-server", "gum-js-loop", "gmain",
            "frida-agent", "frida-gadget", "re.frida.server"
        )

        try {
            val process = Runtime.getRuntime().exec("ps")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                line?.let { processLine ->
                    val columns = processLine.trim().split(Regex("\\s+"))
                    if (columns.size >= 2) {
                        val fullCommand = columns.last()
                        val executableName = fullCommand.substringAfterLast("/")

                        for (fridaExec in fridaExecutables) {
                            if (executableName == fridaExec || fullCommand.endsWith("/$fridaExec")) {
                                reader.close()
                                return true
                            }
                        }

                        if ((executableName == "frida" || fullCommand.endsWith("/frida")) &&
                            !fullCommand.contains("/data/data/") &&
                            !fullCommand.contains("/data/app/")
                        ) {
                            reader.close()
                            return true
                        }
                    }
                }
            }
            reader.close()
            process.waitFor()
        } catch (e: Exception) {
        }
        return false
    }

    // 4. Check /proc/self/maps for Frida libraries
    private fun checkProcMaps(): Boolean {
        val suspiciousKeywords = arrayOf("frida", "gum-js-loop", "libfrida", "gadget", "linjector")
        var matchCount = 0

        try {
            val process = Runtime.getRuntime().exec("cat /proc/self/maps")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            var line: String?

            while (reader.readLine().also { line = it } != null) {
                line?.let {
                    if (it.contains("r--p") || it.contains("r-xp") || it.contains("rw-p") || it.contains("rwxp")) {
                        val lowerLine = it.lowercase(Locale.getDefault())
                        for (keyword in suspiciousKeywords) {
                            if (lowerLine.contains(keyword) && !it.contains("/data/data/") && !it.contains("/data/app/")) {
                                matchCount++
                                if (matchCount >= 2) {
                                    reader.close()
                                    process.destroy()
                                    return true
                                }
                            }
                        }
                    }
                }
            }
            reader.close()
            process.waitFor()
        } catch (e: Exception) {
        }
        return false
    }

    // 5. Check named pipes / file descriptors
    private fun checkNamedPipes(): Boolean {
        try {
            val pid = android.os.Process.myPid()
            val fdDir = File("/proc/$pid/fd")
            if (fdDir.exists() && fdDir.isDirectory) {
                fdDir.listFiles()?.forEach { fdFile ->
                    try {
                        val target = fdFile.canonicalPath
                        val isFridaSuspicious = target.matches(Regex(".*pipe.*frida.*", RegexOption.IGNORE_CASE)) ||
                                               target.matches(Regex(".*pipe.*gum.*", RegexOption.IGNORE_CASE)) ||
                                               target.matches(Regex(".*/frida-server.*", RegexOption.IGNORE_CASE)) ||
                                               target.matches(Regex(".*/re\\.frida\\.server.*", RegexOption.IGNORE_CASE)) ||
                                               (target.startsWith("/dev/socket/") && target.contains("frida", ignoreCase = true)) ||
                                               target.contains("gmain") ||
                                               target.contains("gdbus") ||
                                               target.contains("gum-js-loop")

                        if (isFridaSuspicious && !isAppInternalPath(target)) {
                            return true
                        }
                    } catch (e: Exception) {
                    }
                }
            }
        } catch (e: Exception) {
        }
        return false
    }

    private fun isAppInternalPath(path: String): Boolean {
        return path.contains("/data/data/") ||
               path.contains("/data/app/") ||
               path.contains("/android_asset/") ||
               path.contains("/data/user/") ||
               path.matches(Regex(".*/[a-zA-Z]+\\.[a-zA-Z]+\\.[a-zA-Z]+.*"))
    }

    // 6. Check thread names
    private fun checkThreadNames(): Boolean {
        val suspiciousThreads = arrayOf("gum-js-loop", "gmain", "frida-agent", "gadget-thread")
        try {
            val pid = android.os.Process.myPid()
            val taskDir = File("/proc/$pid/task")
            if (taskDir.exists() && taskDir.isDirectory) {
                taskDir.listFiles()?.forEach { threadDir ->
                    try {
                        val commFile = File(threadDir, "comm")
                        if (commFile.exists()) {
                            val threadName = commFile.readText().trim()
                            for (suspicious in suspiciousThreads) {
                                if (threadName.equals(suspicious, ignoreCase = true)) {
                                    return true
                                }
                            }
                        }
                    } catch (e: Exception) {
                    }
                }
            }
        } catch (e: Exception) {
        }
        return false
    }

    // 7. Check environment variables
    private fun checkEnvironmentVars(): Boolean {
        try {
            System.getenv().forEach { (key, value) ->
                if ("$key=$value".lowercase(Locale.getDefault()).contains("frida")) {
                    return true
                }
            }

            val environFile = File("/proc/self/environ")
            if (environFile.exists()) {
                val content = environFile.readText()
                val envList = content.split("\u0000").filter { it.isNotEmpty() }
                for (env in envList) {
                    if (env.lowercase(Locale.getDefault()).contains("frida")) {
                        return true
                    }
                }
            }
        } catch (e: Exception) {
        }
        return false
    }

    // 8. Check installed Frida/Xposed/LSPosed apps
    private fun checkFridaApps(): Boolean {
        val fridaApps = arrayOf(
            "re.frida.server",
            "de.robv.android.xposed.installer",
            "org.meowcat.edxposed.manager",
            "io.github.lsposed.manager",
            "me.weishu.exp",
            "com.nowsecure.frida",
            "org.frida.fridaclient",
            "com.github.unidbg",
            "jackpal.androidterm",
            "com.offsec.nethunter"
        )

        val allPackages = getAllInstalledPackages()
        return fridaApps.any { it in allPackages }
    }

    // 9. Check native hooks (LSPosed, Xposed, etc.)
    private fun checkNativeLibraries(): Boolean {
        try {
            // Check lspd/zygisk in ps
            val psProcess = Runtime.getRuntime().exec("ps -A")
            val psReader = BufferedReader(InputStreamReader(psProcess.inputStream))
            var line: String?
            while (psReader.readLine().also { line = it } != null) {
                if (line?.contains("lspd") == true || line?.contains("zygisk") == true) {
                    psReader.close()
                    return true
                }
            }
            psReader.close()

            // Check known paths
            val frameworkPaths = arrayOf(
                "/data/adb/lspd",
                "/data/adb/modules/zygisk_lsposed",
                "/data/adb/modules/riru_lsposed",
                "/system/framework/XposedBridge.jar"
            )
            for (path in frameworkPaths) {
                if (File(path).exists()) return true
            }

            // Check stack trace for Xposed
            try {
                throw Exception()
            } catch (e: Exception) {
                for (element in e.stackTrace) {
                    if (element.className.contains("de.robv.android.xposed") ||
                        element.className.contains("io.github.lsposed") ||
                        element.className.contains("org.meowcat.edxposed")) {
                        return true
                    }
                }
            }

            // Check system props
            val xposedProps = arrayOf("ro.lsposed.enable", "persist.lsposed", "init.svc.lspd")
            for (prop in xposedProps) {
                if (System.getProperty(prop).let { it != null && it.isNotEmpty() }) {
                    return true
                }
            }

        } catch (e: Exception) {
        }
        return false
    }

    // 10. Check system properties
    private fun checkSystemProperties(): Boolean {
        val suspiciousProps = arrayOf("ro.frida.server", "ro.debuggable")
        for (prop in suspiciousProps) {
            val value = System.getProperty(prop)
            if (value != null) {
                if (prop.contains("frida") && value.isNotEmpty()) return true
                if (prop == "ro.debuggable" && value == "1") return true
            }
        }
        return false
    }
}