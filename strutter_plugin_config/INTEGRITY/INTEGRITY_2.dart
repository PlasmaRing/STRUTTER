import 'dart:async';
import 'package:flutter/services.dart';

class IntegrityCheckNodbgV1Plugin {
  static const MethodChannel _channel = MethodChannel('integrity_check_nodbg_v1_plugin');

  static Future<String> getApkSignature() async {
    final String signature = await _channel.invokeMethod('getApkSignature');
    return signature;
  }
}