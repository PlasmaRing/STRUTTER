import 'dart:async';
import 'package:flutter/services.dart';

class RootDetectionNodbgV1Plugin {
  static const MethodChannel _channel = MethodChannel('root_detection_nodbg_v1_plugin');

  /// Mengecek apakah device rooted
  static Future<bool> get isDeviceRooted async {
    final bool result = await _channel.invokeMethod('isDeviceRooted');
    return result;
  }

  /// Bisa tambahkan method lain (contoh: cek emulator, dll)
}