import React, { useState } from 'react';
import { StyleSheet, SafeAreaView, StatusBar, View, Text } from 'react-native';
import IntakeScreen from './src/screens/IntakeScreen';
import ScanningScreen from './src/screens/ScanningScreen';
import ResultsScreen from './src/screens/ResultsScreen';
import { theme } from './src/theme';

const API_BASE_URL = 'http://localhost:8000'; // Replace with server host

export default function App() {
  const [currentStep, setCurrentStep] = useState('intake'); // 'intake' | 'scanning' | 'results'
  const [progressPercent, setProgressPercent] = useState(15);
  const [currentStepMessage, setCurrentStepMessage] = useState('');
  const [scanResult, setScanResult] = useState(null);

  const startScan = async (url, contextMessage) => {
    setCurrentStep('scanning');
    setProgressPercent(15);
    setCurrentStepMessage('Provisioning Zero-Trust Chromium sandbox...');

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, context_message: contextMessage }),
      });

      if (!response.ok) {
        throw new Error('Failed to initiate scan');
      }

      const initialScan = await response.json();
      const jobId = initialScan.id;

      // Poll scan completion
      const pollInterval = setInterval(async () => {
        try {
          const res = await fetch(`${API_BASE_URL}/api/v1/scans/${jobId}`);
          if (res.ok) {
            const data = await res.json();
            if (data.status === 'COMPLETED') {
              clearInterval(pollInterval);
              setScanResult(data);
              setProgressPercent(100);
              setCurrentStep('results');
            } else if (data.status === 'PROCESSING') {
              setProgressPercent(65);
              setCurrentStepMessage('Evaluating 6 Threat Factors in sandbox...');
            }
          }
        } catch (e) {
          console.error(e);
        }
      }, 1500);

    } catch (e) {
      console.error(e);
      alert('Error initiating scan: ' + e.message);
      setCurrentStep('intake');
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor={theme.colors.bgDark} />
      
      {/* Mobile Header */}
      <View style={styles.header}>
        <View style={styles.brand}>
          <Text style={styles.brandIcon}>🛡️</Text>
          <View>
            <Text style={styles.brandTitle}>DECEPTIGUARD</Text>
            <Text style={styles.brandSub}>ZERO-TRUST CYBER AI</Text>
          </View>
        </View>
      </View>

      {/* 3-Step Screen Router */}
      {currentStep === 'intake' && (
        <IntakeScreen onStartScan={startScan} apiBaseUrl={API_BASE_URL} />
      )}
      {currentStep === 'scanning' && (
        <ScanningScreen progressPercent={progressPercent} currentStepMessage={currentStepMessage} />
      )}
      {currentStep === 'results' && (
        <ResultsScreen scanData={scanResult} onNewScan={() => setCurrentStep('intake')} apiBaseUrl={API_BASE_URL} />
      )}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: theme.colors.bgDark,
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingVertical: 12,
    borderBottomWidth: 1,
    borderBottomColor: 'rgba(6, 182, 212, 0.3)',
    backgroundColor: 'rgba(14, 23, 38, 0.95)',
  },
  brand: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  brandIcon: {
    fontSize: 22,
  },
  brandTitle: {
    fontSize: 16,
    fontWeight: '900',
    color: '#fff',
    letterSpacing: 0.5,
  },
  brandSub: {
    fontSize: 9,
    fontFamily: 'monospace',
    color: theme.colors.turquoiseNeon,
    fontWeight: '700',
  },
});
