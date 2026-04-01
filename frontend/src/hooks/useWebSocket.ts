/**
 * WebSocket hook for real-time alert streaming.
 * Automatically reconnects on connection loss.
 */
import { useEffect, useRef, useState, useCallback } from 'react'
import type { WSMessage } from '../types'

interface UseWebSocketOptions {
  url: string
  onMessage?: (msg: WSMessage) => void
  enabled?: boolean
}

export function useWebSocket({ url, onMessage, enabled = true }: UseWebSocketOptions) {
  const wsRef = useRef<WebSocket | null>(null)
  const [connected, setConnected] = useState(false)
  const [lastMessage, setLastMessage] = useState<WSMessage | null>(null)
  const reconnectTimer = useRef<number>()
  const reconnectDelay = useRef(1000)

  const connect = useCallback(() => {
    if (!enabled) return

    const token = localStorage.getItem('access_token')
    if (!token) return

    const wsUrl = `${url}?token=${token}`

    try {
      const ws = new WebSocket(wsUrl)
      wsRef.current = ws

      ws.onopen = () => {
        setConnected(true)
        reconnectDelay.current = 1000 // Reset backoff on successful connection
      }

      ws.onmessage = (event) => {
        try {
          const msg: WSMessage = JSON.parse(event.data)
          setLastMessage(msg)
          onMessage?.(msg)
        } catch {
          // Ignore malformed messages
        }
      }

      ws.onclose = () => {
        setConnected(false)
        wsRef.current = null

        // Exponential backoff reconnection (max 30s)
        const delay = Math.min(reconnectDelay.current, 30000)
        reconnectDelay.current = delay * 1.5
        reconnectTimer.current = window.setTimeout(connect, delay)
      }

      ws.onerror = () => {
        ws.close()
      }
    } catch {
      setConnected(false)
    }
  }, [url, enabled, onMessage])

  useEffect(() => {
    connect()
    return () => {
      clearTimeout(reconnectTimer.current)
      wsRef.current?.close()
    }
  }, [connect])

  const send = useCallback((data: unknown) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data))
    }
  }, [])

  return { connected, lastMessage, send }
}
