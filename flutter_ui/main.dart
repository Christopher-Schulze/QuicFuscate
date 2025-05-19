import 'package:flutter/material.dart';

void main() {
  runApp(MyApp());
}

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: Text('quicSand VPN UI')),
        body: Center(child: Text('Konfigurations-UI Placeholder')),
      ),
    );
  }
}
