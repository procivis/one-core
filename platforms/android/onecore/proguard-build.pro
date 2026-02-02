-keep class ch.procivis.one.core.** { *; }

# rustls-platform-verifier
-dontobfuscate
-keep class org.rustls.platformverifier.CertificateVerifier {
    verifyCertificateChain(
        android.content.Context,
        java.lang.String,
        java.lang.String,
        java.lang.String[],
        byte[],
        long,
        byte[][]
    );
}
-keep class org.rustls.platformverifier.StatusCode { *; }
-keep class org.rustls.platformverifier.VerificationResult { *; }