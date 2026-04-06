import { useState, useRef, useEffect, useCallback } from 'react'
import { Bot, Send, User, Zap, Shield, Siren, RefreshCw, AlertTriangle, Square } from 'lucide-react'
import toast from 'react-hot-toast'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Message {
  id:        string
  role:      'user' | 'assistant'
  content:   string
  timestamp: Date
  sources?:  string[]
  actions?:  string[]
  streaming?: boolean   // true while tokens are still arriving
  error?:    boolean
}

// ─── Quick prompts ────────────────────────────────────────────────────────────

const QUICK_PROMPTS = [
  { icon: AlertTriangle, label: 'Explain latest alert',  text: 'Explain the most recent critical alert in detail.' },
  { icon: Shield,        label: 'Response guidance',     text: 'What are the most important actions I should take right now based on current threats?' },
  { icon: Siren,         label: 'Active incidents',      text: 'Give me a summary of all open incidents and their priority.' },
  { icon: Zap,           label: 'Top risks',             text: 'What are the top 3 highest risk IPs currently active in the system?' },
]

// ─── Streaming fetch helper ───────────────────────────────────────────────────

const BASE = '/api/v1/soc-assistant'

async function* streamSSE(
  url: string,
  body: object,
  signal: AbortSignal,
): AsyncGenerator<string> {
  const token = localStorage.getItem('access_token')
  const response = await fetch(url, {
    method:  'POST',
    headers: {
      'Content-Type':  'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body:   JSON.stringify(body),
    signal,
  })

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`)
  }

  const reader  = response.body!.getReader()
  const decoder = new TextDecoder()
  let   buffer  = ''

  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break

      buffer += decoder.decode(value, { stream: true })
      const lines = buffer.split('\n')
      buffer = lines.pop() ?? ''    // keep incomplete line in buffer

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue
        const data = line.slice(6)
        if (data === '[DONE]') return
        // Unescape newlines that were escaped server-side
        yield data.replace(/\\n/g, '\n').replace(/\\\\/g, '\\')
      }
    }
  } finally {
    reader.releaseLock()
  }
}

// ─── MessageBubble ────────────────────────────────────────────────────────────

function MessageBubble({ msg }: { msg: Message }) {
  const isUser = msg.role === 'user'

  return (
    <div className={`flex items-start gap-3 ${isUser ? 'flex-row-reverse' : ''}`}>
      {/* Avatar */}
      <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 mt-0.5 ${
        isUser
          ? 'bg-cyan-500/20 border border-cyan-500/30'
          : msg.error
          ? 'bg-red-500/20 border border-red-500/30'
          : 'bg-purple-500/20 border border-purple-500/30'
      }`}>
        {isUser
          ? <User className="w-4 h-4 text-cyan-300" />
          : <Bot  className={`w-4 h-4 ${msg.error ? 'text-red-300' : 'text-purple-300'}`} />
        }
      </div>

      {/* Bubble */}
      <div className={`max-w-[82%] space-y-2 flex flex-col ${isUser ? 'items-end' : 'items-start'}`}>
        <div className={`rounded-2xl px-4 py-3 text-sm leading-relaxed ${
          isUser
            ? 'bg-cyan-500/10 border border-cyan-500/20 text-gray-200 rounded-tr-sm'
            : msg.error
            ? 'bg-red-900/20 border border-red-700/40 text-red-300 rounded-tl-sm'
            : 'bg-gray-800/80 border border-gray-700/60 text-gray-200 rounded-tl-sm'
        }`}>
          {/* Streaming text with blinking cursor */}
          <p className="whitespace-pre-wrap">
            {msg.content}
            {msg.streaming && (
              <span className="inline-block w-0.5 h-4 bg-purple-400 ml-0.5 align-middle animate-pulse" />
            )}
          </p>
        </div>

        {/* Sources */}
        {!isUser && msg.sources && msg.sources.length > 0 && !msg.streaming && (
          <div className="flex flex-wrap gap-1 px-1">
            {msg.sources.map(s => (
              <span key={s} className="text-[10px] px-1.5 py-0.5 rounded bg-gray-700/60 text-gray-500 border border-gray-700">
                {s.replace(/_/g, ' ')}
              </span>
            ))}
          </div>
        )}

        {/* Recommended actions */}
        {!isUser && msg.actions && msg.actions.length > 0 && !msg.streaming && (
          <div className="space-y-1 px-1 w-full">
            <p className="text-[10px] text-gray-600 uppercase tracking-wider">Recommended Actions</p>
            {msg.actions.map((a, i) => (
              <div key={i} className="flex items-start gap-2 text-xs text-gray-400">
                <span className="text-cyan-500 shrink-0">{i + 1}.</span>
                {a}
              </div>
            ))}
          </div>
        )}

        <span className="text-[10px] text-gray-600 px-1">
          {msg.timestamp.toLocaleTimeString()}
        </span>
      </div>
    </div>
  )
}

// ─── Typing indicator (shown while waiting for first token) ──────────────────

function TypingIndicator() {
  return (
    <div className="flex items-start gap-3">
      <div className="w-8 h-8 rounded-full bg-purple-500/20 border border-purple-500/30 flex items-center justify-center shrink-0">
        <Bot className="w-4 h-4 text-purple-300" />
      </div>
      <div className="bg-gray-800/80 border border-gray-700/60 rounded-2xl rounded-tl-sm px-4 py-3">
        <div className="flex gap-1.5 items-center">
          {[0, 1, 2].map(i => (
            <span
              key={i}
              className="w-2 h-2 rounded-full bg-purple-400 animate-bounce"
              style={{ animationDelay: `${i * 0.18}s` }}
            />
          ))}
          <span className="text-xs text-gray-500 ml-1">Thinking…</span>
        </div>
      </div>
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function SOCAssistantPage() {
  const [messages, setMessages]     = useState<Message[]>([{
    id:        'welcome',
    role:      'assistant',
    content:   'Hello! I\'m your AI SOC Assistant powered by your local LLM.\n\nI can help you:\n• Explain security alerts in plain English\n• Provide incident response guidance\n• Analyse threat patterns and attack behaviours\n• Recommend mitigation steps\n\nAsk me anything, or use a quick prompt below.',
    timestamp: new Date(),
  }])
  const [input, setInput]           = useState('')
  const [isLoading, setIsLoading]   = useState(false)
  const [alertId, setAlertId]       = useState('')
  const [mode, setMode]             = useState<'chat' | 'explain' | 'advise'>('chat')
  const bottomRef                   = useRef<HTMLDivElement>(null)
  const abortRef                    = useRef<AbortController | null>(null)

  // Auto-scroll to bottom whenever messages change
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  // ── Core: stream a message ────────────────────────────────────────────────

  const sendMessage = useCallback(async (text?: string) => {
    const question = (text ?? input).trim()
    if (!question || isLoading) return

    setInput('')

    // Add user bubble
    setMessages(prev => [...prev, {
      id:        crypto.randomUUID(),
      role:      'user',
      content:   question,
      timestamp: new Date(),
    }])

    // Add empty assistant bubble — we'll fill it as tokens arrive
    const assistantId = crypto.randomUUID()
    setMessages(prev => [...prev, {
      id:        assistantId,
      role:      'assistant',
      content:   '',
      timestamp: new Date(),
      streaming: true,
    }])

    setIsLoading(true)
    const ctrl = new AbortController()
    abortRef.current = ctrl

    try {
      // Pick the correct streaming endpoint
      let url: string
      let body: object

      if (mode === 'explain' && alertId) {
        url  = `${BASE}/stream/explain/${alertId}`
        body = {}
      } else if (mode === 'advise' && alertId) {
        url  = `${BASE}/stream/advise/${alertId}`
        body = {}
      } else {
        url  = `${BASE}/stream/ask`
        body = { question }
      }

      let receivedAny = false

      for await (const token of streamSSE(url, body, ctrl.signal)) {
        receivedAny = true
        setMessages(prev =>
          prev.map(m =>
            m.id === assistantId
              ? { ...m, content: m.content + token }
              : m
          )
        )
      }

      // Mark streaming done
      setMessages(prev =>
        prev.map(m =>
          m.id === assistantId
            ? {
                ...m,
                streaming: false,
                content: receivedAny
                  ? m.content
                  : '⚠ No response received. Please check Ollama is running (`ollama serve`) and the model is loaded (`ollama pull gemma3:12b`).',
                error: !receivedAny,
              }
            : m
        )
      )
    } catch (err: any) {
      if (err?.name === 'AbortError') {
        // User manually stopped — just close the cursor
        setMessages(prev =>
          prev.map(m =>
            m.id === assistantId ? { ...m, streaming: false } : m
          )
        )
      } else {
        setMessages(prev =>
          prev.map(m =>
            m.id === assistantId
              ? {
                  ...m,
                  streaming: false,
                  error:     true,
                  content:   '⚠ The AI assistant is currently unavailable.\nPlease check that Ollama is running with `ollama serve` and the model is loaded with `ollama pull gemma3:12b`.',
                }
              : m
          )
        )
      }
    } finally {
      setIsLoading(false)
      abortRef.current = null
    }
  }, [input, isLoading, mode, alertId])

  const stopStream = () => {
    abortRef.current?.abort()
  }

  const clearChat = () => {
    stopStream()
    setMessages([{
      id:        crypto.randomUUID(),
      role:      'assistant',
      content:   'Chat cleared. How can I help you?',
      timestamp: new Date(),
    }])
  }

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="p-6 flex flex-col" style={{ height: 'calc(100vh - 64px)' }}>

      {/* Header */}
      <div className="flex items-center justify-between mb-5 shrink-0">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Bot className="w-6 h-6 text-purple-400" />
            AI SOC Assistant
          </h1>
          <p className="text-sm text-gray-400 mt-0.5">
            Powered by gemma3:12b via Ollama · Streaming responses
          </p>
        </div>
        <button
          onClick={clearChat}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-gray-800 border border-gray-700 text-gray-400 text-sm hover:text-gray-200 transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Clear
        </button>
      </div>

      {/* Mode Selector */}
      <div className="flex items-center gap-3 mb-4 shrink-0 flex-wrap">
        <div className="flex gap-1 bg-gray-800/60 border border-gray-700/50 rounded-xl p-1">
          {([
            { key: 'chat',    label: 'Chat'          },
            { key: 'explain', label: 'Explain Alert' },
            { key: 'advise',  label: 'Get Advice'    },
          ] as const).map(m => (
            <button
              key={m.key}
              onClick={() => setMode(m.key)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                mode === m.key
                  ? 'bg-purple-500/20 text-purple-300 border border-purple-500/20'
                  : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              {m.label}
            </button>
          ))}
        </div>

        {mode !== 'chat' && (
          <input
            value={alertId}
            onChange={e => setAlertId(e.target.value)}
            placeholder="Alert ID"
            className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-500 w-28 font-mono"
          />
        )}
      </div>

      {/* Messages area */}
      <div className="flex-1 overflow-y-auto space-y-5 mb-4 min-h-0 pr-1">
        {messages.map(msg => <MessageBubble key={msg.id} msg={msg} />)}

        {/* Typing dots shown only BEFORE the first token arrives */}
        {isLoading && messages[messages.length - 1]?.content === '' && (
          <TypingIndicator />
        )}

        <div ref={bottomRef} />
      </div>

      {/* Quick prompts — show only at start */}
      {messages.length <= 1 && (
        <div className="grid grid-cols-2 gap-2 mb-4 shrink-0">
          {QUICK_PROMPTS.map(p => (
            <button
              key={p.label}
              onClick={() => sendMessage(p.text)}
              disabled={isLoading}
              className="flex items-center gap-2 px-3 py-2.5 rounded-xl bg-gray-800/60 border border-gray-700/50 text-sm text-gray-300 hover:border-gray-600 hover:text-gray-200 transition-colors text-left disabled:opacity-40"
            >
              <p.icon className="w-3.5 h-3.5 text-gray-500 shrink-0" />
              {p.label}
            </button>
          ))}
        </div>
      )}

      {/* Input row */}
      <div className="flex gap-3 shrink-0">
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && !e.shiftKey && !isLoading && sendMessage()}
          placeholder={
            mode === 'explain' ? `Ask about alert ${alertId || '???'}…`   :
            mode === 'advise'  ? `Advice for alert ${alertId || '???'}…`  :
            'Ask the SOC assistant anything…'
          }
          disabled={isLoading && !abortRef.current}
          className="flex-1 px-4 py-3 bg-gray-800 border border-gray-700 rounded-xl text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-500 disabled:opacity-50"
        />

        {/* Send / Stop button */}
        {isLoading ? (
          <button
            onClick={stopStream}
            className="px-4 py-3 rounded-xl bg-red-500/15 border border-red-500/30 text-red-300 hover:bg-red-500/25 transition-colors"
            title="Stop generating"
          >
            <Square className="w-4 h-4" />
          </button>
        ) : (
          <button
            onClick={() => sendMessage()}
            disabled={!input.trim()}
            className="px-4 py-3 rounded-xl bg-purple-500/15 border border-purple-500/30 text-purple-300 hover:bg-purple-500/25 transition-colors disabled:opacity-40"
          >
            <Send className="w-4 h-4" />
          </button>
        )}
      </div>
    </div>
  )
}
