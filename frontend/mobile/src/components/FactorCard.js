import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { theme } from '../theme';

export default function FactorCard({ icon, name, factorData, defaultTitle }) {
  const rating = factorData?.rating || 'SAFE';
  const title = factorData?.title || defaultTitle;
  const explanation = factorData?.explanation || 'Factor evaluated as standard / safe.';
  const highlight = factorData?.highlight_badge || rating;

  const getBadgeColor = (r) => {
    if (r === 'MALICIOUS') return theme.colors.riskRed;
    if (r === 'SUSPICIOUS') return theme.colors.riskYellow;
    return theme.colors.riskGreen;
  };

  return (
    <View style={styles.card}>
      <View style={styles.header}>
        <Text style={styles.icon}>{icon}</Text>
        <View style={styles.badgeContainer}>
          <Text style={styles.name}>{name}</Text>
          <View style={[styles.badge, { borderColor: getBadgeColor(rating) }]}>
            <Text style={[styles.badgeText, { color: getBadgeColor(rating) }]}>{rating}</Text>
          </View>
        </View>
      </View>
      <Text style={styles.title}>{title}</Text>
      <Text style={styles.explanation}>{explanation}</Text>
      <View style={styles.tag}>
        <Text style={styles.tagText}>{highlight}</Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    backgroundColor: theme.colors.bgCard,
    borderColor: 'rgba(148, 163, 184, 0.2)',
    borderWidth: 1,
    borderRadius: 12,
    padding: 16,
    marginBottom: 12,
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  icon: {
    fontSize: 22,
  },
  badgeContainer: {
    alignItems: 'flex-end',
  },
  name: {
    fontSize: 11,
    fontFamily: 'monospace',
    color: theme.colors.textDim,
    textTransform: 'uppercase',
    fontWeight: '700',
  },
  badge: {
    borderWidth: 1,
    borderRadius: 4,
    paddingHorizontal: 6,
    paddingVertical: 2,
    marginTop: 4,
  },
  badgeText: {
    fontSize: 10,
    fontWeight: '800',
    fontFamily: 'monospace',
  },
  title: {
    fontSize: 14,
    fontWeight: '700',
    color: theme.colors.textMain,
    marginBottom: 4,
  },
  explanation: {
    fontSize: 12,
    color: theme.colors.textMuted,
    lineHeight: 18,
    marginBottom: 8,
  },
  tag: {
    alignSelf: 'flex-start',
    backgroundColor: 'rgba(0, 229, 255, 0.08)',
    borderColor: 'rgba(0, 229, 255, 0.25)',
    borderWidth: 1,
    borderRadius: 4,
    paddingHorizontal: 8,
    paddingVertical: 3,
  },
  tagText: {
    fontSize: 10,
    color: theme.colors.turquoiseNeon,
    fontFamily: 'monospace',
  },
});
