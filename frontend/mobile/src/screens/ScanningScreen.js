import React from 'react';
import { View, Text, StyleSheet, ActivityIndicator } from 'react-native';
import { theme } from '../theme';

export default function ScanningScreen({ progressPercent, currentStepMessage }) {
  const steps = [
    '1. Zero-Trust Sandbox Isolation',
    '2. DOM De-cloaking & Telemetry',
    '3. Viewport Simulation Capture',
    '4. 6-Factor Multimodal Reasoning',
    '5. Decoy Credential Synthesis',
    '6. Playwright Decoy Tarpitting',
    '7. Dossier Assembly',
  ];

  return (
    <View style={styles.container}>
      <View style={styles.badge}>
        <Text style={styles.badgeText}>STEP 2 OF 3 • REAL-TIME PIPELINE</Text>
      </View>

      <Text style={styles.title}>Isolated Sandbox Execution</Text>
      <Text style={styles.sub}>{currentStepMessage || 'Executing zero-trust sandboxed browser scan...'}</Text>

      {/* Progress Bar */}
      <View style={styles.progressBg}>
        <View style={[styles.progressFill, { width: `${progressPercent}%` }]} />
      </View>
      <Text style={styles.progressText}>{progressPercent}% COMPLETE</Text>

      {/* Steps List */}
      <View style={styles.stepsBox}>
        {steps.map((s, idx) => (
          <View key={idx} style={styles.stepItem}>
            <View style={styles.stepDot} />
            <Text style={styles.stepText}>{s}</Text>
          </View>
        ))}
      </View>

      <ActivityIndicator color={theme.colors.turquoiseNeon} size="large" style={{ marginTop: 24 }} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: theme.colors.bgDark,
    padding: 24,
    justifyContent: 'center',
  },
  badge: {
    alignSelf: 'flex-start',
    backgroundColor: 'rgba(0, 229, 255, 0.1)',
    borderColor: 'rgba(0, 229, 255, 0.3)',
    borderWidth: 1,
    borderRadius: 6,
    paddingHorizontal: 8,
    paddingVertical: 4,
    marginBottom: 12,
  },
  badgeText: {
    fontSize: 11,
    color: theme.colors.turquoiseNeon,
    fontFamily: 'monospace',
    fontWeight: '800',
  },
  title: {
    fontSize: 22,
    fontWeight: '900',
    color: theme.colors.textMain,
    marginBottom: 6,
  },
  sub: {
    fontSize: 13,
    color: theme.colors.turquoiseNeon,
    fontFamily: 'monospace',
    marginBottom: 20,
  },
  progressBg: {
    height: 10,
    backgroundColor: 'rgba(255, 255, 255, 0.08)',
    borderRadius: 999,
    overflow: 'hidden',
    marginBottom: 8,
  },
  progressFill: {
    height: '100%',
    backgroundColor: theme.colors.turquoiseNeon,
  },
  progressText: {
    fontSize: 12,
    fontFamily: 'monospace',
    color: theme.colors.textDim,
    textAlign: 'right',
    marginBottom: 24,
  },
  stepsBox: {
    backgroundColor: theme.colors.bgCard,
    borderRadius: 10,
    padding: 16,
    borderColor: 'rgba(148, 163, 184, 0.2)',
    borderWidth: 1,
    gap: 8,
  },
  stepItem: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  stepDot: {
    width: 6,
    height: 6,
    borderRadius: 3,
    backgroundColor: theme.colors.turquoiseCyan,
  },
  stepText: {
    fontSize: 12,
    fontFamily: 'monospace',
    color: theme.colors.textMuted,
  },
});
