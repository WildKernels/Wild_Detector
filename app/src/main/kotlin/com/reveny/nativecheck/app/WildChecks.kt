package com.reveny.nativecheck.app

import android.app.AppOpsManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate
import kotlin.math.abs

/*
 * Kotlin-side ports of the Uber Driver (com.ubercab.driver 4.602.10001)
 * detections that need Android framework APIs rather than native calls.
 *
 * Every check here is present in the Uber app:
 *  - manager packages: the 9 root-manager names compiled into Uber's
 *    RootBeer layer (DEX constant pool; 6 also in its manifest <queries>)
 *  - mock location: MockLocationHandler / Location.isFromMockProvider
 *  - time tamper: SntpClientRepo / NtpClock / TimeTamperingUseCase, plus
 *    libse.so's boot-time baseline (CLOCK_MONOTONIC - sysinfo.uptime)
 *  - key attestation: Presidio KeyAttestationApi (KeyGenParameterSpec +
 *    setAttestationChallenge + attestation certificate chain +
 *    KeyAttestationSecurityLevel / StrongBoxUnavailableException)
 *
 * Not ported (not in the Uber app, or not portable):
 *  - Play Integrity / SafetyNet: server-issued verdicts, need GMS + backend
 *  - hasMockCertVerifier: inspects Uber's own TLS stack at runtime
 */
object WildChecks {

    private const val GROUP_PACKAGES = "Root manager packages"
    private const val GROUP_MOCK = "Mock location"
    private const val GROUP_TIME = "Time / clock"
    private const val GROUP_ATTEST = "Hardware attestation"

    /** Clock-drift threshold for the NTP check (Uber's exact limit is
     *  server-configured; 2 minutes is the working default here). */
    private const val CLOCK_DRIFT_LIMIT_MS = 120_000L

    private fun det(name: String, group: String, desc: String, evidence: String? = null, detected: Boolean = true) =
        DetectionData(
            name,
            if (evidence.isNullOrBlank()) desc else "$desc\n\n$evidence",
            group,
            detected
        )

    // -----------------------------------------------------------------
    // Root manager packages (DEX/RootBeer constant pool)
    // -----------------------------------------------------------------

    private val MANAGER_PACKAGES = arrayOf(
        "com.topjohnwu.magisk",
        "eu.chainfire.supersu",
        "com.genymotion.superuser",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "cyanogenmod.superuser",
        "com.noshufou.android.su",
        "com.ramdroid.appquarantine",
        "com.zachspong.temprootremovejb",
    )

    private const val DESC_PACKAGES =
        "One of the 9 root-manager package names compiled into Uber's " +
        "RootBeer layer is installed on this device. Note: inside the Uber " +
        "app only 6 of these are declared in its manifest <queries>, so its " +
        "Magisk / cyanogenmod / genymotion lookups are visibility-dead on " +
        "targetSdk 30+; this app declares QUERY_ALL_PACKAGES, so all 9 " +
        "checks actually resolve."

    private fun managerPackages(context: Context): List<DetectionData> {
        val pm = context.packageManager
        val hits = mutableListOf<Pair<String, String>>()
        for (pkg in MANAGER_PACKAGES) {
            try {
                val info = pm.getPackageInfo(pkg, 0)
                val label = info.applicationInfo?.let { ai ->
                    try {
                        pm.getApplicationLabel(ai).toString()
                    } catch (_: Exception) {
                        pkg
                    }
                } ?: pkg
                val version = info.versionName?.let { " $it" } ?: ""
                hits += pkg to "$label$version"
            } catch (_: PackageManager.NameNotFoundException) {
                // not installed — clean for this package
            }
        }
        return if (hits.isEmpty()) {
            det(
                "root manager packages",
                GROUP_PACKAGES,
                DESC_PACKAGES,
                "none of the 9 root-manager packages are installed",
                detected = false
            ).let(::listOf)
        } else {
            det(
                "root manager packages",
                GROUP_PACKAGES,
                DESC_PACKAGES,
                hits.joinToString("\n") { "${it.first} (${it.second})" }
            ).let(::listOf)
        }
    }

    // -----------------------------------------------------------------
    // Mock location (MockLocationHandler port)
    // -----------------------------------------------------------------

    private const val DESC_MOCK =
        "Uber inspects every location fix with Location.isFromMockProvider() " +
        "and LocationManager.isMockingEnabled() (MockLocationHandler, " +
        "compiled into com.ubercab.driver) — a driver app cares because GPS " +
        "spoofing is position fraud. A detector app receives no fixes, so " +
        "the equivalent signal is used here: whether any package holds the " +
        "mock-location app-op (the developer-settings 'mock location app' " +
        "toggle)."

    /**
     * The mock-location app-op id and getPackagesForOp() were removed from
     * the public SDK stubs (API 34+) but remain callable at runtime, so the
     * op is resolved reflectively ("android:mock_location" -> id -> holders).
     * Everything is wrapped: if the reflection path is blocked on some
     * future Android, the check silently reports nothing rather than
     * failing the scan.
     */
    private fun mockLocation(context: Context): List<DetectionData> {
        val holders = try {
            val opsClass = AppOpsManager::class.java
            val strToOp = opsClass.getMethod("strOpToOp", String::class.java)
            val opId = strToOp.invoke(null, AppOpsManager.OPSTR_MOCK_LOCATION) as Int
            val getPkgs = opsClass.getMethod("getPackagesForOp", Int::class.javaPrimitiveType)
            (getPkgs.invoke(context.getSystemService(Context.APP_OPS_SERVICE), opId) as? Array<*>)
                ?.filterIsInstance<String>().orEmpty()
        } catch (_: Throwable) {
            null
        }?.filter { it.isNotBlank() }
        return when {
            holders == null -> det(
                "mock location providers",
                GROUP_MOCK,
                DESC_MOCK,
                "the app-ops reflection path was blocked on this Android " +
                    "version — check unavailable",
                detected = false
            ).let(::listOf)
            holders.isEmpty() -> det(
                "mock location providers",
                GROUP_MOCK,
                DESC_MOCK,
                "no packages hold the mock-location app-op",
                detected = false
            ).let(::listOf)
            else -> det(
                "mock location providers",
                GROUP_MOCK,
                DESC_MOCK,
                holders.joinToString("\n")
            ).let(::listOf)
        }
    }

    // -----------------------------------------------------------------
    // Time / clock tamper (SntpClientRepo + NtpTimeVerifying port)
    // -----------------------------------------------------------------

    private const val DESC_TIME =
        "Uber keeps an independent clock: SntpClientRepo performs SNTP " +
        "round-trips (NtpClock / NtpTimeSyncRxWorker) and TimeTamperingUseCase " +
        "flags a wall clock that diverges; libse.so additionally snapshots " +
        "boot_time = CLOCK_MONOTONIC - sysinfo.uptime at load (DAT_001aa450) " +
        "to catch clock resets. This is the one-shot equivalent: an SNTP " +
        "query (UDP/123) compared against the device wall clock. Drift over " +
        "120 s is flagged."

    /** SNTP client-mode query; returns server-time minus device-time in ms. */
    private fun sntpOffsetMs(): Long {
        var lastError: Exception? = null
        for (host in arrayOf("time.google.com", "time.nist.gov")) {
            try {
                DatagramSocket().use { socket ->
                    socket.soTimeout = 3000
                    val address = InetAddress.getByName(host)
                    val request = ByteArray(48)
                    request[0] = 0x1B // LI=0, VN=3, Mode=3 (client)
                    socket.send(DatagramPacket(request, request.size, address, 123))
                    val buf = ByteArray(48)
                    socket.receive(DatagramPacket(buf, buf.size))

                    var seconds = 0L
                    for (i in 0 until 4) seconds = (seconds shl 8) or (buf[40 + i].toLong() and 0xFF)
                    var fraction = 0L
                    for (i in 0 until 4) fraction = (fraction shl 8) or (buf[44 + i].toLong() and 0xFF)
                    val ntpMillis = seconds * 1000L + fraction * 1000L / (1L shl 32) -
                        2208988800000L // NTP (1900) -> Unix (1970) epoch
                    return ntpMillis - System.currentTimeMillis()
                }
            } catch (e: Exception) {
                lastError = e
            }
        }
        throw lastError ?: IllegalStateException("no NTP host reachable")
    }

    private fun timeCheck(): List<DetectionData> {
        return try {
            val offset = sntpOffsetMs()
            det(
                "clock vs NTP",
                GROUP_TIME,
                DESC_TIME,
                "NTP - device clock = ${offset} ms (limit ±$CLOCK_DRIFT_LIMIT_MS ms)",
                detected = abs(offset) > CLOCK_DRIFT_LIMIT_MS
            ).let(::listOf)
        } catch (t: Throwable) {
            det(
                "clock vs NTP",
                GROUP_TIME,
                DESC_TIME,
                "SNTP query could not run (${t.javaClass.simpleName}: " +
                    "${t.message}) — the clock could not be verified",
                detected = false
            ).let(::listOf)
        }
    }

    // -----------------------------------------------------------------
    // Hardware key attestation (Presidio KeyAttestationApi port)
    // -----------------------------------------------------------------

    private const val ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"

    private const val DESC_ATTEST =
        "This is the wall that root hiding cannot pass. Uber's Presidio " +
        "KeyAttestationApi generates an EC key in AndroidKeyStore with " +
        "setAttestationChallenge() and reads back the attestation " +
        "certificate chain (KeyAttestationApi.b() -> Certificate[]), which " +
        "its backend validates against Google's root. This check runs the " +
        "same code path locally and reads the chain's KeyDescription: the " +
        "attestation security level (Software / TrustedEnvironment / " +
        "StrongBox) and the RootOfTrust record (verifiedBootState, " +
        "deviceLocked) — the hardware's own verdict on the boot chain."

    private class Tlv(val tag: Int, val contentStart: Int, val contentLen: Int, val next: Int)

    private fun parseTlv(b: ByteArray, p: Int): Tlv {
        var i = p
        val first = b[i++].toInt() and 0xFF
        var tag = first
        if (first and 0x1F == 0x1F) { // high tag number form (e.g. [704])
            tag = 0
            var tb: Int
            do {
                tb = b[i++].toInt() and 0xFF
                tag = (tag shl 7) or (tb and 0x7F)
            } while (tb and 0x80 != 0)
        }
        var len = b[i++].toInt() and 0xFF
        if (len and 0x80 != 0) {
            val n = len and 0x7F
            len = 0
            repeat(n) { len = (len shl 8) or (b[i++].toInt() and 0xFF) }
        }
        return Tlv(tag, i, len, i + len)
    }

    private class Attestation(
        val securityLevel: Int,          // 0 software, 1 TEE, 2 StrongBox
        val verifiedBootState: Int?,     // 0 verified, 1 self-signed, 2 unverified, 3 failed
        val deviceLocked: Boolean?,
    )

    /** Walks the KeyDescription ::= SEQUENCE of a key attestation extension. */
    private fun parseAttestation(cert: X509Certificate): Attestation? {
        val extVal = cert.getExtensionValue(ATTESTATION_OID) ?: return null
        val outer = parseTlv(extVal, 0)              // OCTET STRING wrapper
        if (outer.tag != 0x04) return null
        val keyDesc = parseTlv(extVal, outer.contentStart) // SEQUENCE
        if (keyDesc.tag != 0x30) return null
        var p = keyDesc.contentStart
        val end = keyDesc.contentStart + keyDesc.contentLen
        if (end > extVal.size) return null

        val attVersion = parseTlv(extVal, p)          // INTEGER attestationVersion
        if (attVersion.tag != 0x02) return null
        p = attVersion.next
        val attSec = parseTlv(extVal, p)              // ENUMERATED security level
        if (attSec.tag != 0x0A || attSec.contentLen < 1) return null
        val securityLevel = extVal[attSec.contentStart].toInt() and 0xFF
        p = attSec.next
        p = parseTlv(extVal, p).next                  // INTEGER keymasterVersion
        p = parseTlv(extVal, p).next                  // ENUMERATED keymasterSecurityLevel
        p = parseTlv(extVal, p).next                  // OCTET STRING challenge
        p = parseTlv(extVal, p).next                  // OCTET STRING uniqueId
        p = parseTlv(extVal, p).next                  // SEQUENCE softwareEnforced
        if (p >= end) return Attestation(securityLevel, null, null)
        val tee = parseTlv(extVal, p)                 // SEQUENCE teeEnforced
        if (tee.tag != 0x30) return Attestation(securityLevel, null, null)

        // AuthorizationList: RootOfTrust is context tag [704]
        var s = tee.contentStart
        val send = tee.contentStart + tee.contentLen
        while (s < send) {
            val t = parseTlv(extVal, s)
            if (t.tag == 704) { // RootOfTrust ::= SEQUENCE { ENUM, BOOLEAN, OCTET, OCTET }
                var r = t.contentStart
                val vbs = parseTlv(extVal, r)
                val verifiedBootState = if (vbs.tag == 0x0A && vbs.contentLen >= 1)
                    extVal[vbs.contentStart].toInt() and 0xFF else null
                r = vbs.next
                val dl = parseTlv(extVal, r)
                val deviceLocked = if (dl.tag == 0x01 && dl.contentLen >= 1)
                    extVal[dl.contentStart].toInt() != 0 else null
                return Attestation(securityLevel, verifiedBootState, deviceLocked)
            }
            s = t.next
        }
        return Attestation(securityLevel, null, null)
    }

    private fun securityLevelName(level: Int) = when (level) {
        0 -> "Software"
        1 -> "TrustedEnvironment (TEE)"
        2 -> "StrongBox"
        else -> "unknown($level)"
    }

    private fun verifiedBootStateName(state: Int) = when (state) {
        0 -> "Verified (green)"
        1 -> "SelfSigned (yellow)"
        2 -> "Unverified (orange)"
        3 -> "Failed (red)"
        else -> "unknown($state)"
    }

    private fun attestation(): List<DetectionData> {
        val alias = "wilddet-attest"
        try {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            ks.deleteEntry(alias)

            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            val challenge = "wilddet-${System.currentTimeMillis()}".toByteArray()

            fun buildSpec(strongBox: Boolean): KeyGenParameterSpec {
                val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                if (strongBox) builder.setIsStrongBoxBacked(true) // API 28+, guarded below
                return builder.build()
            }

            if (Build.VERSION.SDK_INT >= 28) {
                // Uber requests StrongBox and catches StrongBoxUnavailableException
                try {
                    kpg.initialize(buildSpec(strongBox = true))
                } catch (_: Exception) {
                    kpg.initialize(buildSpec(strongBox = false))
                }
            } else {
                kpg.initialize(buildSpec(strongBox = false))
            }
            kpg.generateKeyPair()

            val chain = ks.getCertificateChain(alias)
            if (chain == null || chain.isEmpty() || chain[0] !is X509Certificate) {
                ks.deleteEntry(alias)
                return det(
                    "hardware key attestation",
                    GROUP_ATTEST,
                    DESC_ATTEST,
                    "AndroidKeyStore returned no attestation certificate " +
                        "chain — the check could not complete.",
                    detected = true
                ).let(::listOf)
            }
            val parsed = parseAttestation(chain[0] as X509Certificate)
            ks.deleteEntry(alias)

            if (parsed == null) {
                return det(
                    "hardware key attestation",
                    GROUP_ATTEST,
                    DESC_ATTEST,
                    "The attestation extension (OID $ATTESTATION_OID) could " +
                        "not be parsed — this device either lacks hardware " +
                        "attestation or returns a non-standard chain.",
                    detected = true
                ).let(::listOf)
            }

            val evidence = buildString {
                append("attestationSecurityLevel = ${securityLevelName(parsed.securityLevel)}")
                if (parsed.verifiedBootState != null) {
                    append("\nverifiedBootState = ${verifiedBootStateName(parsed.verifiedBootState)}")
                    append("\ndeviceLocked = ${parsed.deviceLocked}")
                }
            }

            val anomalies = mutableListOf<String>()
            if (parsed.securityLevel == 0) {
                anomalies += "keymaster is software-only (runs inside the " +
                    "OS itself, so its guarantees are void on a compromised device)"
            }
            if (parsed.verifiedBootState != null &&
                (parsed.verifiedBootState != 0 || parsed.deviceLocked == false)
            ) {
                anomalies += "boot chain not verified/locked — the hardware " +
                    "RootOfTrust record (the same one Uber's server validates " +
                    "when the attestation chain is uploaded) says the device " +
                    "is not in the Verified/locked state; root hiding cannot " +
                    "change this"
            }

            val fullEvidence = if (anomalies.isEmpty()) {
                evidence
            } else {
                evidence + "\n\nfindings:\n" +
                    anomalies.joinToString("\n") { "- $it" }
            }
            return det(
                "hardware key attestation",
                GROUP_ATTEST,
                DESC_ATTEST,
                fullEvidence,
                detected = anomalies.isNotEmpty()
            ).let(::listOf)
        } catch (t: Throwable) {
            return det(
                "hardware key attestation",
                GROUP_ATTEST,
                DESC_ATTEST,
                "The check could not run: ${t.javaClass.simpleName}: ${t.message}",
                detected = true
            ).let(::listOf)
        }
    }

    // -----------------------------------------------------------------

    fun detect(context: Context, experimental: Boolean): List<DetectionData> {
        val out = mutableListOf<DetectionData>()
        out += managerPackages(context)
        out += mockLocation(context)
        out += timeCheck()
        out += attestation()
        return out
    }
}
