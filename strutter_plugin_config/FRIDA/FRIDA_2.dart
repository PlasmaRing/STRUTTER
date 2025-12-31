import 'dart:async';
import 'package:flutter/services.dart';

class FridaDetectionNodbgV1Plugin {
  static const MethodChannel _channel = MethodChannel('frida_detection_nodbg_v1_plugin');

  static Future<bool> get isFridaDetected async {
    final bool result = await _channel.invokeMethod('isFridaDetected');
    return result;
  }
}