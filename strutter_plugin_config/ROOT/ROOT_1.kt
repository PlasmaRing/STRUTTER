package com.example.root_detection_nodbg_v1_plugin

import android.os.Build
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import android.content.pm.PackageManager
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.File

class RootDetectionNodbgV1Plugin : FlutterPlugin, MethodChannel.MethodCallHandler {
    private lateinit var channel: MethodChannel
    private lateinit var context: android.content.Context

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(binding.binaryMessenger, "root_detection_nodbg_v1_plugin")
        channel.setMethodCallHandler(this)
        context = binding.applicationContext
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "isDeviceRooted" -> result.success(isRooted())
            else -> result.notImplemented()
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

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
            // Silent
        }

        return allPackages
    }

    private fun isRooted(): Boolean {
        return checkRootFiles() ||
               checkDangerousApps() ||
               checkCloakingApps() ||
               checkBuildTags() ||
               checkSuCommand() ||
               checkRootViaShell() ||
               checkXposedFramework() ||
               checkSystemProperties() ||
               checkNativeHooks() ||
               checkSelinuxStatus() ||
               checkMountPoints() ||
               checkDeveloperSettings() ||
               checkEmulator()
    }

    private fun checkRootFiles(): Boolean {
        val paths = arrayOf(
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su",
            "/vendor/bin/su",
            "/product/bin/su",
            "/product/xbin/su",
            "/product/app/Superuser.apk",
            "/product/app/SuperSU.apk",
            "/product/app/Magisk.apk",
            "/product/app/Kinguser.apk",
            "/system_ext/bin/su",
            "/system_ext/xbin/su",
            "/data/adb/magisk",
            "/data/adb/modules",
            "/data/adb/magisk.db",
            "/data/adb/magisk.img",
            "/data/adb/magisk_merge.img",
            "/sbin/.magisk",
            "/debug_ramdisk/.magisk",
            "/dev/magisk",
            "/cache/magisk.log",
            "/data/magisk.log",
            "/system/app/Superuser.apk",
            "/system/app/SuperSU.apk",
            "/system/etc/init.d/99SuperSUDaemon",
            "/system/xbin/daemonsu",
            "/system/xbin/sugote",
            "/system/xbin/sugote-mksh",
            "/system/xbin/supolicy",
            "/system/bin/.ext/.su",
            "/system/usr/we-need-root/su-backup",
            "/system/xbin/mu",
            "/system/app/Kinguser.apk",
            "/data/data-lib/libking_launcher.so",
            "/system/bin/rt",
            "/system/bin/ku.sud",
            "/system/bin/.usr/.ku",
            "/system/xbin/ku.sud",
            "/system/usr/iku/isu",
            "/system/app/RootExplorer.apk",
            "/dev/com.koushikdutta.superuser.daemon/",
            "/system/framework/XposedBridge.jar",
            "/system/bin/app_process_xposed",
            "/data/data/de.robv.android.xposed.installer/",
            "/product/framework/XposedBridge.jar"
        )
        for (path in paths) {
            if (File(path).exists()) return true
        }
        return false
    }

    private fun checkDangerousApps(): Boolean {
        val dangerousApps = arrayOf(
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "eu.chainfire.supersu.pro",
            "com.noshufou.android.su",
            "com.thirdparty.superuser",
            "com.koushikdutta.superuser",
            "com.yellowes.su",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "com.kingoapp.root",
            "com.kingoroot.android",
            "com.halfdroid.framaroot",
            "com.zhiqupk.root.global",
            "com.alephzain.framaroot",
            "stericson.busybox",
            "stericson.busybox.donate",
            "ru.meefik.busybox",
            "com.speedsoftware.rootexplorer",
            "com.jrummy.root.browserfree",
            "com.jrummy.liberty.toolbox",
            "com.joeykrim.rootcheck",
            "com.joeykrim.rootcheckpro",
            "com.devadvance.rootchecker2",
            "com.abcdjdj.rootverifier",
            "jackpal.androidterm",
            "com.spartacusrex.spartacuside",
            "com.google.android.terminal",
            "com.chelpus.lackypatch",
            "com.dimonvideo.luckypatcher",
            "com.forpda.lp",
            "com.koushikdutta.rommanager",
            "com.koushikdutta.rommanager.license",
            "com.keramidas.TitaniumBackup",
            "com.keramidas.TitaniumBackupPro",
            "catch_.me_.if_.you_.can_",
            "com.ramdroid.appquarantine",
            "com.zachspong.temprootremovejb",
            "com.tinyhack.zygiskreflutter"
        )
        val allPackages = getAllInstalledPackages()
        return dangerousApps.any { it in allPackages }
    }

    private fun checkCloakingApps(): Boolean {
        val cloakingApps = arrayOf(
            "com.topjohnwu.magisk",
            "io.github.huskydg.magisk",
            "com.github.rikka.shamiko",
            "io.github.lsposed.manager.zygisk",
            "org.lsposed.manager",
            "de.robv.android.xposed.installer",
            "org.meowcat.edxposed.manager",
            "com.devadvance.rootcloak",
            "com.devadvance.rootcloakplus",
            "com.amphoras.hidemyroot",
            "com.amphoras.hidemyrootpremium",
            "com.tsng.hidemyapplist",
            "com.github.megatronking.hideapplist",
            "ru.zdevs.zygisk.detector",
            "riru.core",
            "com.github.rikka.riru",
            "eu.faircode.xlua",
            "com.oasisfeng.island",
            "moe.shizuku.privileged.api",
            "com.cilenco.fakeinfo",
            "com.android.chrome.fakeinfo",
            "app.greyshirts.sslcapturepro",
            "com.github.fox2code.mmm",
            "com.fox2code.mmm",
            "com.scottyab.rootbeer.sample",
            "com.joeykrim.rootcheck",
            "com.saurik.substrate",
            "com.formyhm.hideapplication",
            "com.trianguloy.llscript"
        )
        val allPackages = getAllInstalledPackages()
        return cloakingApps.any { it in allPackages }
    }

    private fun checkBuildTags(): Boolean {
        val buildTags = Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }

    private fun checkSuCommand(): Boolean {
        val suPaths = arrayOf(
            "/system/xbin/which",
            "/system/bin/which",
            "/sbin/which",
            "/usr/bin/which"
        )
        for (whichPath in suPaths) {
            try {
                val process = Runtime.getRuntime().exec(arrayOf(whichPath, "su"))
                if (process.waitFor() == 0) return true
            } catch (_: Exception) {
                // Ignore
            }
        }
        return false
    }

    private fun checkRootViaShell(): Boolean {
        try {
            val process = Runtime.getRuntime().exec("su")
            if (process.waitFor() == 0) return true
        } catch (_: Exception) {
            // Expected
        }

        try {
            val process = Runtime.getRuntime().exec("ls /data/data/")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val output = reader.readText()
            reader.close()
            process.waitFor()

            if (output.contains("com.") && output.length > 50) return true
        } catch (_: Exception) {
            // Expected
        }

        return false
    }

    private fun checkXposedFramework(): Boolean {
        try {
            Class.forName("de.robv.android.xposed.XposedBridge")
            return true
        } catch (_: ClassNotFoundException) {
            // Not found
        }

        val lsposedIndicators = arrayOf(
            "/data/adb/lspd",
            "/data/adb/modules/lsposed",
            "/system/framework/lspd.dex",
            "/system/lib/libriru_lspd.so",
            "/system/lib64/libriru_lspd.so"
        )

        for (path in lsposedIndicators) {
            if (File(path).exists()) return true
        }

        try {
            throw RuntimeException()
        } catch (e: RuntimeException) {
            for (element in e.stackTrace) {
                if (element.className.contains("de.robv.android.xposed") ||
                    element.className.contains("org.lsposed")) {
                    return true
                }
            }
        }

        return false
    }

    private fun checkSystemProperties(): Boolean {
        val suspiciousProps = mapOf(
            "ro.debuggable" to "1",
            "ro.secure" to "0",
            "ro.build.type" to "userdebug",
            "ro.build.tags" to "test-keys",
            "service.adb.root" to "1",
            "ro.kernel.qemu" to "1"
        )

        for ((prop, suspiciousValue) in suspiciousProps) {
            try {
                val process = Runtime.getRuntime().exec("getprop $prop")
                val reader = BufferedReader(InputStreamReader(process.inputStream))
                val value = reader.readLine()?.trim()
                process.waitFor()
                reader.close()

                if (value == suspiciousValue) return true
            } catch (_: Exception) {
                // Ignore
            }
        }
        return false
    }

    private fun checkNativeHooks(): Boolean {
        val suspiciousLibs = arrayOf(
            "libxposed", "libriru", "liblspd", "libdobby",
            "libfrida", "libsubstrate", "libhook", "libnativehelper_compat"
        )

        try {
            val process = Runtime.getRuntime().exec("cat /proc/self/maps")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            var line: String?

            while (reader.readLine().also { line = it } != null) {
                line?.let {
                    for (lib in suspiciousLibs) {
                        if (it.contains(lib)) {
                            reader.close()
                            return true
                        }
                    }
                }
            }
            reader.close()
            process.waitFor()
        } catch (_: Exception) {
            // Ignore
        }
        return false
    }

    private fun checkSelinuxStatus(): Boolean {
        try {
            val process = Runtime.getRuntime().exec("getenforce")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val status = reader.readLine()?.trim()
            process.waitFor()
            reader.close()

            if (status != null && (status.equals("Permissive", ignoreCase = true) ||
                                   status.equals("Disabled", ignoreCase = true))) {
                return true
            }

            val selinuxPaths = arrayOf("/sys/fs/selinux/enforce", "/selinux/enforce")
            for (path in selinuxPaths) {
                try {
                    val file = File(path)
                    if (file.exists() && file.canRead()) {
                        if (file.readText().trim() == "0") return true
                    }
                } catch (_: Exception) {
                    // Continue
                }
            }
        } catch (_: Exception) {
            // Ignore
        }
        return false
    }

    private fun checkMountPoints(): Boolean {
        val suspiciousMounts = arrayOf("magisk", "xposed", "/data/adb", "tmpfs /sbin", "tmpfs /system")

        try {
            val process = Runtime.getRuntime().exec("cat /proc/mounts")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            var line: String?

            while (reader.readLine().also { line = it } != null) {
                line?.let {
                    for (mount in suspiciousMounts) {
                        if (it.contains(mount) && (it.contains("/system") || it.contains("/sbin") || it.contains("magisk"))) {
                            reader.close()
                            return true
                        }
                    }
                }
            }
            reader.close()
            process.waitFor()
        } catch (_: Exception) {
            // Ignore
        }
        return false
    }

    private fun checkDeveloperSettings(): Boolean {
        return try {
            val resolver = context.contentResolver
            val adbEnabled = android.provider.Settings.Global.getInt(
                resolver, android.provider.Settings.Global.ADB_ENABLED, 0
            ) == 1

            if (adbEnabled) {
                // USB debugging is currently treated as a root indicator; change return true to return false if you want it as a warning only.
                true
            } else {
                false
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun checkEmulator(): Boolean {
        val indicators = arrayOf(
            Build.FINGERPRINT.contains("generic"),
            Build.FINGERPRINT.contains("unknown"),
            Build.MODEL.contains("google_sdk"),
            Build.MODEL.contains("Emulator") || Build.MODEL.contains("Android SDK"),
            Build.MANUFACTURER.contains("Genymotion"),
            Build.BRAND.startsWith("generic", ignoreCase = true),
            Build.DEVICE.startsWith("generic", ignoreCase = true),
            Build.PRODUCT.contains("sdk") ||
            Build.PRODUCT.contains("emulator") ||
            Build.PRODUCT.contains("simulator")
        )
        // Emulator detection is generally not considered “rooted,” so it does not return true by default and is only a reference for additional risk.
        return false
    }
}