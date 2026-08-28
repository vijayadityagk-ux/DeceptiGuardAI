/**
 * PhishTrap WebSocket Pipeline Client
 */
class PhishTrapWebSocket {
  constructor(jobId, onEventCallback, onErrorCallback) {
    this.jobId = jobId;
    this.onEvent = onEventCallback;
    this.onError = onErrorCallback;
    this.socket = null;
    this.connect();
  }

  connect() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host || 'localhost:8000';
    const wsUrl = `${protocol}//${host}/api/v1/ws/scan/${this.jobId}`;

    console.log(`[PhishTrap WS] Connecting to ${wsUrl}`);
    this.socket = new WebSocket(wsUrl);

    this.socket.onopen = () => {
      console.log(`[PhishTrap WS] Connected for job ${this.jobId}`);
    };

    this.socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (this.onEvent) {
          this.onEvent(data);
        }
      } catch (err) {
        console.error('[PhishTrap WS] Event parse error:', err);
      }
    };

    this.socket.onerror = (err) => {
      console.error('[PhishTrap WS] Socket error:', err);
      if (this.onError) this.onError(err);
    };

    this.socket.onclose = () => {
      console.log('[PhishTrap WS] Connection closed');
    };
  }

  close() {
    if (this.socket) {
      this.socket.close();
    }
  }
}
