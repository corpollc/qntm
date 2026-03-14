import React from 'react';
import { Box, Text } from 'ink';
import { theme } from '../lib/theme.js';

interface GateRequestBody {
  type: string;
  recipe_name?: string;
  conv_id: string;
  request_id: string;
  verb: string;
  target_endpoint: string;
  target_service: string;
  target_url: string;
  expires_at: string;
  signer_kid: string;
  arguments?: Record<string, string>;
}

interface GateApprovalBody {
  type: string;
  request_id: string;
  signer_kid: string;
}

interface GateExecutedBody {
  type: string;
  request_id: string;
  execution_status_code: number;
}

interface GateResultBody {
  type: string;
  request_id: string;
  status_code: number;
  content_type?: string;
  body?: string;
}

function tryParse(text: string): Record<string, unknown> | null {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function statusColor(code: number): string {
  if (code >= 500) return theme.error;
  if (code >= 400) return theme.warning;
  if (code >= 300) return theme.info;
  return theme.success;
}

function formatBody(body: string, maxLen: number = 300): string {
  const parsed = tryParse(body);
  if (parsed) {
    const pretty = JSON.stringify(parsed, null, 2);
    return pretty.length > maxLen ? pretty.slice(0, maxLen) + '\u2026' : pretty;
  }
  return body.length > maxLen ? body.slice(0, maxLen) + '\u2026' : body;
}

/** Label + value on one line */
function Field({ label, value }: { label: string; value: string }) {
  return (
    <Text>
      <Text bold>{label}: </Text>
      <Text dimColor>{value}</Text>
    </Text>
  );
}

interface GateCardProps {
  bodyType: string;
  text: string;
  direction: 'incoming' | 'outgoing';
}

export default function GateCard({ bodyType, text, direction }: GateCardProps) {
  const parsed = tryParse(text);
  if (!parsed) {
    return <Text>{text}</Text>;
  }

  const type = (parsed.type as string) || bodyType;

  // ── gate.request ──────────────────────────────────────────────────
  if (type === 'gate.request') {
    const req = parsed as unknown as GateRequestBody;
    const isExpired = req.expires_at ? new Date(req.expires_at) < new Date() : false;
    const hasArgs = req.arguments && Object.keys(req.arguments).length > 0;

    return (
      <Box flexDirection="column" marginTop={1}>
        <Box
          flexDirection="column"
          borderStyle="double"
          borderColor={theme.gateRequest}
          paddingX={1}
        >
          {/* Header */}
          <Text bold color={theme.gateRequest}>
            {'\u26a1'} API Request {req.recipe_name ? `[${req.recipe_name}]` : ''}
          </Text>

          {/* Metadata */}
          <Box flexDirection="column" marginTop={1}>
            <Text>
              <Text bold color={theme.gateRequest}>{req.verb}</Text>
              <Text> {req.target_url || req.target_endpoint}</Text>
            </Text>
            <Field label="Service" value={req.target_service} />
            <Field label="Conv" value={req.conv_id.slice(0, 8)} />
            <Field label="Request" value={req.request_id.slice(0, 12)} />
            <Field label="Signer" value={req.signer_kid.slice(0, 12)} />
          </Box>

          {/* Arguments */}
          {hasArgs && (
            <Box flexDirection="column" marginTop={1}>
              <Text bold>Arguments:</Text>
              {Object.entries(req.arguments!).map(([k, v]) => (
                <Text key={k}>
                  <Text>  </Text>
                  <Text bold>{k}</Text>
                  <Text dimColor> = {v}</Text>
                </Text>
              ))}
            </Box>
          )}

          {/* Expiry / actions */}
          <Box marginTop={1} flexDirection="column">
            {isExpired ? (
              <Text bold color={theme.gateError}>{'\u2718'} EXPIRED</Text>
            ) : (
              <Field label="Expires" value={req.expires_at} />
            )}
            {direction === 'incoming' && !isExpired && (
              <Text color={theme.gateApproval} bold>
                {'\u279c'} Press &apos;a&apos; to approve | /approve {req.request_id.slice(0, 8)}
              </Text>
            )}
          </Box>
        </Box>
      </Box>
    );
  }

  // ── gate.approval ─────────────────────────────────────────────────
  if (type === 'gate.approval') {
    const appr = parsed as unknown as GateApprovalBody;
    return (
      <Box flexDirection="column" marginTop={1}>
        <Box
          flexDirection="column"
          borderStyle="double"
          borderColor={theme.gateApproval}
          paddingX={1}
        >
          <Text bold color={theme.gateApproval}>
            {'\u2714'} APPROVED
          </Text>
          <Text dimColor>{'\u2500'.repeat(30)}</Text>
          <Field label="Request" value={appr.request_id.slice(0, 12)} />
          <Field label="Signer" value={appr.signer_kid.slice(0, 12)} />
        </Box>
      </Box>
    );
  }

  // ── gate.executed ─────────────────────────────────────────────────
  if (type === 'gate.executed') {
    const exec = parsed as unknown as GateExecutedBody;
    const color = statusColor(exec.execution_status_code);
    return (
      <Box flexDirection="column" marginTop={1}>
        <Box
          flexDirection="column"
          borderStyle="double"
          borderColor={theme.gateExecuted}
          paddingX={1}
        >
          <Text bold color={theme.gateExecuted}>
            {'\u25b6'} Executed
          </Text>
          <Field label="Request" value={exec.request_id.slice(0, 12)} />
          <Text>
            <Text bold>HTTP: </Text>
            <Text bold color={color}>{String(exec.execution_status_code)}</Text>
          </Text>
        </Box>
      </Box>
    );
  }

  // ── gate.result ───────────────────────────────────────────────────
  if (type === 'gate.result') {
    const res = parsed as unknown as GateResultBody;
    const color = statusColor(res.status_code);
    const borderColor = res.status_code < 400 ? theme.gateResult : theme.gateError;

    return (
      <Box flexDirection="column" marginTop={1}>
        <Box
          flexDirection="column"
          borderStyle="double"
          borderColor={borderColor}
          paddingX={1}
        >
          {/* Header */}
          <Text bold color={borderColor}>
            {'\u2709'} API Response
          </Text>

          {/* Metadata */}
          <Box flexDirection="column" marginTop={1}>
            <Field label="Request" value={res.request_id.slice(0, 12)} />
            <Text>
              <Text bold>Status: </Text>
              <Text bold color={color}>{String(res.status_code)}</Text>
            </Text>
            {res.content_type && (
              <Field label="Content-Type" value={res.content_type} />
            )}
          </Box>

          {/* Response body in nested box */}
          {res.body && (
            <Box
              flexDirection="column"
              borderStyle="single"
              borderColor={theme.border}
              paddingX={1}
              marginTop={1}
            >
              <Text dimColor>{formatBody(res.body)}</Text>
            </Box>
          )}
        </Box>
      </Box>
    );
  }

  // ── Unknown gate type ─────────────────────────────────────────────
  return (
    <Box flexDirection="column" marginTop={1}>
      <Box borderStyle="double" borderColor={theme.border} paddingX={1}>
        <Text dimColor>[{type}] {text.slice(0, 200)}</Text>
      </Box>
    </Box>
  );
}
