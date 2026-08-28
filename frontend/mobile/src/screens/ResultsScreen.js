import React from 'react';
import { View, Text, StyleSheet, ScrollView, Image, TouchableOpacity } from 'react-native';
import FactorCard from '../components/FactorCard';
import { theme } from '../theme';

export default function ResultsScreen({ scanData, onNewScan, apiBaseUrl }) {
  const score = Math.round(scanData?.risk_score || 0);
  const threatLevel = scanData?.threat_level || 'SAFE';
  const detectedLang = scanData?.detected_language || 'English';

  const getScoreColor = () => {
    if (score >= 66 || threatLevel === 'MALICIOUS') return theme.colors.riskRed;
    if (score >= 31 || threatLevel === 'SUSPICIOUS') return theme.colors.riskYellow;
    return theme.colors.riskGreen;
  };

  const screenshotUrl = scanData?.screenshot_filename 
    ? `${apiBaseUrl}/storage/screenshots/${scanData.screenshot_filename}` 
    : null;

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {/* Top Bar */}
      <View style={styles.topBar}>
        <TouchableOpacity style={styles.backBtn} onPress={onNewScan}>
          <Text style={styles.backBtnText}>← Scan New Target</Text>
        </TouchableOpacity>
        <View style={styles.langBadge}>
          <Text style={styles.langText}>🌐 {detectedLang}</Text>
        </View>
      </View>

      {/* Brand Spoofing Banner */}
      {scanData?.target_brand && threatLevel === 'MALICIOUS' && (
        <View style={styles.brandBanner}>
          <Text style={styles.brandBannerTitle}>🚨 ZERO-DAY BRAND SPOOFING</Text>
          <Text style={styles.brandBannerText}>
            Claims '{scanData.target_brand}' identity on unauthorized domain.
          </Text>
        </View>
      )}

      {/* Risk Gauge */}
      <View style={styles.riskCard}>
        <View style={[styles.circle, { borderColor: getScoreColor() }]}>
          <Text style={[styles.scoreValue, { color: getScoreColor() }]}>{score}</Text>
          <Text style={styles.scoreLabel}>RISK LEVEL (%)</Text>
        </View>
        <View style={[styles.threatBadge, { borderColor: getScoreColor() }]}>
          <Text style={[styles.threatBadgeText, { color: getScoreColor() }]}>{threatLevel}</Text>
        </View>
        <Text style={styles.legend}>0-30 Green • 31-65 Yellow • 66-100 Red</Text>
      </View>

      {/* Summary */}
      <View style={styles.summaryCard}>
        <Text style={styles.summaryKicker}>EXECUTIVE SUMMARY ({detectedLang})</Text>
        <Text style={styles.summaryText}>{scanData?.summary || 'Scan complete.'}</Text>
      </View>

      {/* 6 Factor Cards */}
      <Text style={styles.sectionHeader}>📊 6-FACTOR THREAT BREAKDOWN</Text>

      <FactorCard
        icon="✉️"
        name="Message Suspicion"
        factorData={scanData?.factor_message_suspicion}
        defaultTitle="Urgency & Pretexting"
      />
      <FactorCard
        icon="🌐"
        name="URL Domain Name"
        factorData={scanData?.factor_url_domain_name}
        defaultTitle="Domain Host Structure"
      />
      <FactorCard
        icon="🔒"
        name="URL Legitness"
        factorData={scanData?.factor_url_legitness}
        defaultTitle="Protocol & Route Integrity"
      />
      <FactorCard
        icon="🎭"
        name="Brand Spoofing"
        factorData={scanData?.factor_brand_spoofing}
        defaultTitle="Brand Identity Dissonance"
      />
      <FactorCard
        icon="⚡"
        name="Malicious Intent"
        factorData={scanData?.factor_malicious_intent}
        defaultTitle="Attack Classification"
      />
      <FactorCard
        icon="🚨"
        name="Deceptive Claims"
        factorData={scanData?.factor_deceptive_claims}
        defaultTitle="Deceptive Pretexts"
      />

      {/* Sandbox Screenshot Simulation */}
      {screenshotUrl && (
        <View style={styles.screenshotCard}>
          <Text style={styles.screenshotTitle}>📷 SANDBOX VIEWPORT SIMULATION</Text>
          <Image source={{ uri: screenshotUrl }} style={styles.screenshotImg} resizeMode="cover" />
        </View>
      )}

      {/* Active Honeypot Receipts */}
      {scanData?.honeypot_triggered && scanData?.honeypot_logs?.length > 0 && (
        <View style={styles.honeypotCard}>
          <Text style={styles.honeypotTitle}>🪤 ACTIVE HONEYPOT DECOY RECEIPT</Text>
          <Text style={styles.honeypotSub}>
            Synthetic credentials injected into attacker portal to exhaust resources.
          </Text>
          <View style={styles.wastedBadge}>
            <Text style={styles.wastedText}>
              ⏱️ Wasted: {scanData.honeypot_logs[0]?.attacker_resource_wasted_seconds}s
            </Text>
          </View>
        </View>
      )}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: theme.colors.bgDark,
  },
  content: {
    padding: 20,
    paddingBottom: 40,
  },
  topBar: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 16,
  },
  backBtn: {
    backgroundColor: 'rgba(0, 229, 255, 0.1)',
    borderColor: theme.colors.turquoiseCyan,
    borderWidth: 1,
    borderRadius: 8,
    paddingHorizontal: 12,
    paddingVertical: 6,
  },
  backBtnText: {
    color: theme.colors.turquoiseNeon,
    fontSize: 12,
    fontWeight: '700',
  },
  langBadge: {
    backgroundColor: 'rgba(255, 255, 255, 0.08)',
    borderRadius: 8,
    paddingHorizontal: 10,
    paddingVertical: 6,
  },
  langText: {
    color: theme.colors.textMuted,
    fontSize: 11,
    fontFamily: 'monospace',
  },
  brandBanner: {
    backgroundColor: 'rgba(239, 68, 68, 0.15)',
    borderColor: theme.colors.riskRed,
    borderWidth: 1,
    borderRadius: 10,
    padding: 12,
    marginBottom: 16,
  },
  brandBannerTitle: {
    color: theme.colors.riskRed,
    fontWeight: '900',
    fontSize: 13,
  },
  brandBannerText: {
    color: theme.colors.textMuted,
    fontSize: 11,
    marginTop: 2,
  },
  riskCard: {
    backgroundColor: theme.colors.bgCard,
    borderColor: 'rgba(148, 163, 184, 0.2)',
    borderWidth: 1,
    borderRadius: 14,
    padding: 20,
    alignItems: 'center',
    marginBottom: 16,
  },
  circle: {
    width: 120,
    height: 120,
    borderRadius: 60,
    borderWidth: 8,
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 10,
  },
  scoreValue: {
    fontSize: 32,
    fontWeight: '900',
    fontFamily: 'monospace',
  },
  scoreLabel: {
    fontSize: 9,
    fontFamily: 'monospace',
    color: theme.colors.textDim,
    fontWeight: '700',
  },
  threatBadge: {
    borderWidth: 1,
    borderRadius: 999,
    paddingHorizontal: 14,
    paddingVertical: 4,
    marginBottom: 8,
  },
  threatBadgeText: {
    fontWeight: '900',
    fontSize: 12,
    fontFamily: 'monospace',
    letterSpacing: 0.5,
  },
  legend: {
    fontSize: 10,
    color: theme.colors.textDim,
    fontFamily: 'monospace',
  },
  summaryCard: {
    backgroundColor: theme.colors.bgCard,
    borderColor: 'rgba(6, 182, 212, 0.3)',
    borderWidth: 1,
    borderRadius: 12,
    padding: 16,
    marginBottom: 20,
  },
  summaryKicker: {
    fontSize: 10,
    fontFamily: 'monospace',
    color: theme.colors.turquoiseNeon,
    fontWeight: '800',
    marginBottom: 4,
  },
  summaryText: {
    fontSize: 13,
    color: theme.colors.textMain,
    lineHeight: 19,
  },
  sectionHeader: {
    fontSize: 13,
    fontFamily: 'monospace',
    fontWeight: '800',
    color: theme.colors.turquoiseNeon,
    marginBottom: 12,
  },
  screenshotCard: {
    backgroundColor: theme.colors.bgCard,
    borderRadius: 12,
    padding: 14,
    marginTop: 10,
    marginBottom: 16,
    borderColor: 'rgba(148, 163, 184, 0.2)',
    borderWidth: 1,
  },
  screenshotTitle: {
    fontSize: 11,
    fontFamily: 'monospace',
    fontWeight: '700',
    color: theme.colors.turquoiseNeon,
    marginBottom: 10,
  },
  screenshotImg: {
    width: '100%',
    height: 180,
    borderRadius: 8,
  },
  honeypotCard: {
    backgroundColor: 'rgba(168, 85, 247, 0.1)',
    borderColor: theme.colors.violetHoneypot,
    borderWidth: 1,
    borderRadius: 12,
    padding: 16,
    marginBottom: 20,
  },
  honeypotTitle: {
    fontSize: 12,
    fontFamily: 'monospace',
    fontWeight: '800',
    color: theme.colors.violetHoneypot,
    marginBottom: 4,
  },
  honeypotSub: {
    fontSize: 11,
    color: theme.colors.textMuted,
    lineHeight: 16,
  },
  wastedBadge: {
    backgroundColor: 'rgba(168, 85, 247, 0.25)',
    alignSelf: 'flex-start',
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 6,
    marginTop: 8,
  },
  wastedText: {
    fontSize: 11,
    fontWeight: '700',
    color: theme.colors.violetHoneypot,
    fontFamily: 'monospace',
  },
});
