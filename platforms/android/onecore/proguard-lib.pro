# java-native-access
-dontwarn java.awt.*
-keep class com.sun.jna.* { *; }
-keep class * extends com.sun.jna.* { public *; }

# rustls-platform-verifier
-keep, includedescriptorclasses class org.rustls.platformverifier.** { *; }