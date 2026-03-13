import React from 'react';
import { Box, Text } from 'ink';

interface GateRequestBody {
  type: string;
  recipe_name?: string;
  org_id: string;
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

  if (type === 'gate.request') {
    const req = parsed as unknown as GateRequestBody;
    const isExpired = req.expires_at ? new Date(req.expires_at) < new Date() : false;
    const hasArgs = req.arguments && Object.keys(req.arguments).length > 0;

    return (
      <Box flexDirection="column" borderStyle="round" borderColor="yellow" paddingX={1}>
        <Text bold color="yellow">
          {'\u26a1'} API Request {req.recipe_name ? `[${req.recipe_name}]` : ''}
        </Text>
        <Text>
          <Text bold>{req.verb}</Text> {req.target_url || req.target_endpoint}
        </Text>
        <Text dimColor>service: {req.target_service} | org: {req.org_id.slice(0, 8)}</Text>
        <Text dimColor>req: {req.request_id.slice(0, 12)}</Text>
        {hasArgs && (
          <Box flexDirection="column" marginTop={1}>
            <Text dimColor>Arguments:</Text>
            {Object.entries(req.arguments!).map(([k, v]) => (
              <Text key={k}>  {k}: {v}</Text>
            ))}
          </Box>
        )}
        {isExpired ? (
          <Text color="red">EXPIRED</Text>
        ) : (
          <Text dimColor>expires: {req.expires_at}</Text>
        )}
        {direction === 'incoming' && !isExpired && (
          <Text color="green">Press 'a' to approve | /approve {req.request_id.slice(0, 8)}</Text>
        )}
      </Box>
    );
  }

  if (type === 'gate.approval') {
    const appr = parsed as unknown as GateApprovalBody;
    return (
      <Box borderStyle="round" borderColor="green" paddingX={1}>
        <Text color="green">
          {'\u2714'} Approved request {appr.request_id.slice(0, 12)} by {appr.signer_kid.slice(0, 12)}
        </Text>
      </Box>
    );
  }

  if (type === 'gate.executed') {
    const exec = parsed as unknown as GateExecutedBody;
    const color = exec.execution_status_code < 400 ? 'green' : 'red';
    return (
      <Box borderStyle="round" borderColor={color} paddingX={1}>
        <Text color={color}>
          {'\u25b6'} Request executed {exec.request_id.slice(0, 12)} - HTTP {exec.execution_status_code}
        </Text>
      </Box>
    );
  }

  if (type === 'gate.result') {
    const res = parsed as unknown as GateResultBody;
    const color = res.status_code < 400 ? 'green' : 'red';
    return (
      <Box flexDirection="column" borderStyle="round" borderColor={color} paddingX={1}>
        <Text color={color}>
          {'\u2709'} API Response {res.request_id.slice(0, 12)} - HTTP {res.status_code}
        </Text>
        {res.content_type && <Text dimColor>content-type: {res.content_type}</Text>}
        {res.body && (
          <Text>{res.body.length > 500 ? res.body.slice(0, 500) + '...' : res.body}</Text>
        )}
      </Box>
    );
  }

  // Unknown gate type — render raw
  return (
    <Box borderStyle="round" borderColor="gray" paddingX={1}>
      <Text dimColor>[{type}] {text.slice(0, 200)}</Text>
    </Box>
  );
}
