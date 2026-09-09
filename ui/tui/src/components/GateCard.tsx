/** Compact authenticated gateway summaries. Actions open the complete review. */
import { parseGatewayBody } from '@corpollc/qntm';
export function gatewaySummary(bodyType: string, text: string): string {
  try {
    const body = parseGatewayBody(bodyType, text);
    switch (body.type) {
      case 'gate.request': return `API request ${body.request_id}\n${body.verb} ${body.target_url}\n${body.required_approvals} approvals requested; expires ${body.expires_at}\n/approve ${body.request_id.slice(0, 8)} or /disapprove ${body.request_id.slice(0, 8)} to review`;
      case 'gate.approval': return `Approval for ${body.request_id} from ${body.signer_kid}`;
      case 'gate.disapproval': return `Vote withdrawn for ${body.request_id} by ${body.signer_kid}`;
      case 'gate.executed': return `Gateway executed ${body.request_id}: HTTP ${body.execution_status_code}`;
      case 'gate.result': return `Gateway result ${body.request_id}: HTTP ${body.status_code}\n${body.body ?? ''}`;
      case 'gate.secret': return `Sealed credential ${body.secret_id} for ${body.service}; gateway ${body.gateway_kid}`;
      case 'gate.promote': return `Gateway invitation ${body.gateway_public_key}; awaiting signed acceptance`;
      case 'gate.accept': return `Gateway accepted in chat: ${body.gateway_public_key}`;
      case 'gov.propose': return `Governance ${body.proposal_id}: ${body.proposal_type}\n/gov-approve ${body.proposal_id.slice(0, 8)} or /gov-disapprove ${body.proposal_id.slice(0, 8)} to review`;
      case 'gov.approve': return `Governance approval for ${body.proposal_id}`;
      case 'gov.disapprove': return `Governance vote withdrawn for ${body.proposal_id}`;
      case 'gov.applied': return `Gateway applied ${body.proposal_type}: ${body.proposal_id}`;
      case 'gov.invalidated': return `Gateway invalidated proposal ${body.proposal_id}`;
      case 'gate.invalidated': return `Gateway invalidated request ${body.request_id}`;
      case 'gate.expired': return `Gateway credential expired for ${body.service}`;
    }
  } catch { return `[unverified ${bodyType}] ${text}`; }
}
