import {
  Alert,
  Box,
  Button,
  Chip,
  FormControlLabel,
  Grid,
  LinearProgress,
  Switch,
  TextField,
  Typography,
} from '@mui/material'
import { Channel } from '@tauri-apps/api/core'
import { useLockFn } from 'ahooks'
import dayjs from 'dayjs'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { BaseEmpty, BasePage } from '@/components/base'
import {
  clearIpOptimizeResult,
  getIpOptimizeResult,
  patchVergeConfig,
  startIpOptimize,
  stopIpOptimize,
  type IpOptimizeEvent,
  type IpOptimizeSummary,
  type IpOptimizeView,
} from '@/services/cmds'
import { showNotice } from '@/services/notice-service'

const STATUS_LABEL_KEYS: Record<string, string> = {
  ok: 'optimize.page.status.ok',
  skip: 'optimize.page.status.skip',
  fail: 'optimize.page.status.fail',
}

const PHASE_LABEL_KEYS = {
  resolve: 'optimize.page.progress.resolve',
  speed: 'optimize.page.progress.speed',
} as const

type EntryRow = {
  name: string
  server: string
  target: string
  latency_ms?: number | null
  status: string
}

type LogLine = { id: number; message: string }

type PhaseProgress = { done: number; total: number }

const OptimizePage = () => {
  const { t } = useTranslation()

  const [view, setView] = useState<IpOptimizeView | null>(null)
  const [enabled, setEnabled] = useState(false)
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState<
    Record<'resolve' | 'speed', PhaseProgress | null>
  >({ resolve: null, speed: null })
  const [rows, setRows] = useState<EntryRow[]>([])
  const [logs, setLogs] = useState<LogLine[]>([])
  const logIdRef = useRef(0)
  const [summary, setSummary] = useState<IpOptimizeSummary | null>(null)
  const [concurrency, setConcurrency] = useState(20)
  const [tcpTimeout, setTcpTimeout] = useState(1000)
  const [dnsTimeout, setDnsTimeout] = useState(3000)
  const [enableDoh, setEnableDoh] = useState(true)

  useEffect(() => {
    void getIpOptimizeResult()
      .then((result) => {
        setView(result)
        setEnabled(result.enabled)
        setSummary(result.profiles[result.profile_uid] ?? null)
      })
      .catch(console.error)
  }, [])

  const appendLog = (message: string) =>
    setLogs((prev) => [
      ...prev.slice(-199),
      { id: logIdRef.current++, message },
    ])

  const start = useLockFn(async () => {
    const channel = new Channel<IpOptimizeEvent>((event) => {
      switch (event.type) {
        case 'log':
          appendLog(event.message)
          break
        case 'progress':
          setProgress((prev) => ({
            ...prev,
            [event.phase]: { done: event.done, total: event.total },
          }))
          break
        case 'entry':
          setRows((prev) => [
            ...prev,
            {
              name: event.name,
              server: event.server,
              target: event.target,
              latency_ms: event.latency_ms,
              status: event.status,
            },
          ])
          break
        case 'done':
          setSummary(event.summary)
          break
      }
    })

    setRunning(true)
    setRows([])
    setLogs([])
    setProgress({ resolve: null, speed: null })
    try {
      const result = await startIpOptimize(
        {
          concurrency,
          tcp_timeout_ms: tcpTimeout,
          dns_timeout_ms: dnsTimeout,
          enable_doh: enableDoh,
        },
        channel,
      )
      setSummary(result)
      if (enabled) {
        // Rebuild the runtime configuration so the stored winners take effect.
        try {
          await patchVergeConfig({ enable_ip_optimize: true })
        } catch (err) {
          showNotice.error('optimize.page.messages.applyFailed', err)
        }
      }
    } catch (err) {
      showNotice.error('optimize.page.messages.startFailed', err)
    } finally {
      setRunning(false)
    }
  })

  const stop = useLockFn(async () => {
    try {
      await stopIpOptimize()
    } catch (err) {
      showNotice.error('optimize.page.messages.stopFailed', err)
    }
  })

  const clear = useLockFn(async () => {
    try {
      await clearIpOptimizeResult(view?.profile_uid)
      setSummary(null)
      setRows([])
      showNotice.success('optimize.page.messages.cleared')
    } catch (err) {
      showNotice.error('optimize.page.messages.applyFailed', err)
    }
  })

  const toggleEnabled = async (checked: boolean) => {
    const previous = enabled
    setEnabled(checked)
    try {
      await patchVergeConfig({ enable_ip_optimize: checked })
    } catch (err) {
      setEnabled(previous)
      showNotice.error('optimize.page.messages.applyFailed', err)
    }
  }

  const stats = summary
    ? t('optimize.page.stats.total', {
        total: summary.domain_nodes + summary.ip_nodes,
        domain: summary.domain_nodes,
        ip: summary.ip_nodes,
      })
    : null

  return (
    <BasePage
      title={t('optimize.page.title')}
      header={
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Button
            variant="contained"
            size="small"
            disabled={running}
            onClick={start}
          >
            {t('optimize.page.actions.start')}
          </Button>
          <Button
            variant="outlined"
            size="small"
            disabled={!running}
            onClick={stop}
          >
            {t('optimize.page.actions.stop')}
          </Button>
          <Button
            variant="text"
            size="small"
            disabled={running || !summary}
            onClick={clear}
          >
            {t('optimize.page.actions.clear')}
          </Button>
        </Box>
      }
    >
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        {t('optimize.page.description')}
      </Typography>

      <Alert severity="info" sx={{ mb: 2 }}>
        <Typography variant="body2">
          {t('optimize.page.notice.directMode')}
        </Typography>
      </Alert>

      <Grid container spacing={2} sx={{ mb: 2 }}>
        <Grid size={{ xs: 6, sm: 3 }}>
          <TextField
            fullWidth
            size="small"
            type="number"
            label={t('optimize.page.params.concurrency')}
            value={concurrency}
            disabled={running}
            onChange={(e) =>
              setConcurrency(Math.max(1, Number(e.target.value) || 1))
            }
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <TextField
            fullWidth
            size="small"
            type="number"
            label={t('optimize.page.params.tcpTimeout')}
            value={tcpTimeout}
            disabled={running}
            onChange={(e) =>
              setTcpTimeout(Math.max(100, Number(e.target.value) || 100))
            }
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <TextField
            fullWidth
            size="small"
            type="number"
            label={t('optimize.page.params.dnsTimeout')}
            value={dnsTimeout}
            disabled={running}
            onChange={(e) =>
              setDnsTimeout(Math.max(500, Number(e.target.value) || 500))
            }
          />
        </Grid>
        <Grid
          size={{ xs: 6, sm: 3 }}
          sx={{ display: 'flex', alignItems: 'center' }}
        >
          <FormControlLabel
            control={
              <Switch
                checked={enableDoh}
                disabled={running}
                onChange={(e) => setEnableDoh(e.target.checked)}
              />
            }
            label={t('optimize.page.params.doh')}
          />
        </Grid>
      </Grid>

      <FormControlLabel
        sx={{ mb: 1 }}
        control={
          <Switch
            checked={enabled}
            onChange={(e) => void toggleEnabled(e.target.checked)}
          />
        }
        label={
          <Box>
            <Typography variant="body2">
              {t('optimize.page.enable.label')}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {t('optimize.page.enable.hint')}
            </Typography>
          </Box>
        }
      />

      {stats && (
        <Typography variant="body2" sx={{ mb: 1 }}>
          {stats}
          {summary && summary.updated_at > 0 && (
            <>
              {' · '}
              {t('optimize.page.stats.updatedAt', {
                time: dayjs(summary.updated_at * 1000).format(
                  'YYYY-MM-DD HH:mm:ss',
                ),
              })}
            </>
          )}
          {summary && summary.optimized_nodes > 0 && (
            <>
              {' · '}
              {t('optimize.page.stats.optimized', {
                count: summary.optimized_nodes,
              })}
            </>
          )}
        </Typography>
      )}

      {running && (
        <Box sx={{ mb: 2 }}>
          {(['resolve', 'speed'] as const).map((phase) => {
            const current = progress[phase]
            return (
              <Box
                key={phase}
                sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}
              >
                <Typography variant="body2" sx={{ minWidth: 64 }}>
                  {t(PHASE_LABEL_KEYS[phase])}
                </Typography>
                <LinearProgress
                  sx={{ flexGrow: 1 }}
                  variant={
                    current && current.total > 0
                      ? 'determinate'
                      : 'indeterminate'
                  }
                  value={
                    current && current.total > 0
                      ? (current.done / current.total) * 100
                      : undefined
                  }
                />
                <Typography
                  variant="caption"
                  sx={{ minWidth: 48, textAlign: 'right' }}
                >
                  {current ? `${current.done}/${current.total}` : ''}
                </Typography>
              </Box>
            )
          })}
        </Box>
      )}

      {rows.length > 0 ? (
        <Box sx={{ overflow: 'auto', flexGrow: 1 }}>
          {rows.map((row) => (
            <Box
              key={`${row.name}|${row.server}|${row.target}`}
              sx={{
                display: 'flex',
                alignItems: 'center',
                gap: 1,
                py: 0.75,
                borderBottom: 1,
                borderColor: 'divider',
                fontSize: 13,
              }}
            >
              <Typography variant="body2" noWrap sx={{ width: 220 }}>
                {row.name}
              </Typography>
              <Typography
                variant="body2"
                noWrap
                color="text.secondary"
                sx={{ flex: 1 }}
              >
                {row.server} → {row.target}
              </Typography>
              <Typography
                variant="body2"
                sx={{ minWidth: 72, textAlign: 'right' }}
              >
                {row.latency_ms != null ? `${row.latency_ms} ms` : '-'}
              </Typography>
              <Chip
                size="small"
                label={t(
                  STATUS_LABEL_KEYS[row.status] ?? 'optimize.page.status.fail',
                )}
                color={
                  row.status === 'ok'
                    ? 'success'
                    : row.status === 'fail'
                      ? 'warning'
                      : 'default'
                }
              />
            </Box>
          ))}
        </Box>
      ) : (
        !running && <BaseEmpty text={t('optimize.page.empty')} />
      )}

      {logs.length > 0 && (
        <Box
          sx={{
            mt: 1,
            maxHeight: 120,
            overflow: 'auto',
            fontFamily: 'monospace',
            fontSize: 12,
            color: 'text.secondary',
          }}
        >
          {logs.map((line) => (
            <div key={line.id}>{line.message}</div>
          ))}
        </Box>
      )}
    </BasePage>
  )
}

export default OptimizePage
