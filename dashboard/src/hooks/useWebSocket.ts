import { useEffect, useRef, useState, useCallback } from 'react';
import type { WebSocketEvent } from '../lib/types';

const WS_URL = (import.meta.env.VITE_WS_URL || 'ws://localhost:8000') + '/ws/events';

interface UseWebSocketOptions {
  onEvent?: (event: WebSocketEvent) => void;
  reconnectInterval?: number;
}

interface WebSocketState {
  connected: boolean;
  lastEvent: WebSocketEvent | null;
  events: WebSocketEvent[];
}

export function useWebSocket(options: UseWebSocketOptions = {}): WebSocketState {
  const { onEvent, reconnectInterval = 3000 } = options;
  const [state, setState] = useState<WebSocketState>({
    connected: false,
    lastEvent: null,
    events: [],
  });
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(true);

  const connect = useCallback(() => {
    if (!mountedRef.current) return;
    try {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!mountedRef.current) return;
        setState(prev => ({ ...prev, connected: true }));
      };

      ws.onmessage = (e) => {
        if (!mountedRef.current) return;
        try {
          const event: WebSocketEvent = JSON.parse(e.data);
          if (event.type === 'keepalive') return;
          setState(prev => ({
            ...prev,
            lastEvent: event,
            events: [event, ...prev.events.slice(0, 99)], // Keep last 100
          }));
          onEvent?.(event);
        } catch {
          // ignore parse errors
        }
      };

      ws.onclose = () => {
        if (!mountedRef.current) return;
        setState(prev => ({ ...prev, connected: false }));
        reconnectTimerRef.current = setTimeout(connect, reconnectInterval);
      };

      ws.onerror = () => {
        ws.close();
      };
    } catch {
      reconnectTimerRef.current = setTimeout(connect, reconnectInterval);
    }
  }, [onEvent, reconnectInterval]);

  useEffect(() => {
    mountedRef.current = true;
    connect();
    return () => {
      mountedRef.current = false;
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      wsRef.current?.close();
    };
  }, [connect]);

  return state;
}
