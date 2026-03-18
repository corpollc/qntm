import { describe, expect, it } from 'vitest'
import { formatGroupEvent, formatGovEvent, type GroupEventDisplay } from './SystemEvents'

describe('formatGroupEvent', () => {
  describe('group_genesis', () => {
    it('formats genesis with group name and member count', () => {
      const body = JSON.stringify({
        group_name: 'Ops Team',
        description: 'Operations group',
        created_at: 1710000000,
        founding_members: [
          { key_id: 'a1b2', public_key: 'pk1', role: 'admin', added_at: 1710000000, added_by: 'a1b2' },
          { key_id: 'c3d4', public_key: 'pk2', role: 'member', added_at: 1710000000, added_by: 'a1b2' },
        ],
      })
      const result = formatGroupEvent('group_genesis', body)
      expect(result).not.toBeNull()
      expect(result!.icon).toBe('group')
      expect(result!.headline).toContain('Ops Team')
      expect(result!.headline).toContain('created')
      expect(result!.detail).toContain('2 members')
    })

    it('formats genesis with single member', () => {
      const body = JSON.stringify({
        group_name: 'Solo',
        description: '',
        created_at: 1710000000,
        founding_members: [
          { key_id: 'a1b2', public_key: 'pk1', role: 'admin', added_at: 1710000000, added_by: 'a1b2' },
        ],
      })
      const result = formatGroupEvent('group_genesis', body)
      expect(result!.detail).toContain('1 member')
    })
  })

  describe('group_add', () => {
    it('formats add with member count', () => {
      const body = JSON.stringify({
        added_at: 1710000000,
        new_members: [
          { key_id: 'c3d4', public_key: 'pk2', role: 'member', added_at: 1710000000, added_by: 'a1b2' },
        ],
      })
      const result = formatGroupEvent('group_add', body, 'Alice')
      expect(result).not.toBeNull()
      expect(result!.icon).toBe('add')
      expect(result!.headline).toContain('Alice')
      expect(result!.headline).toContain('added')
      expect(result!.headline).toContain('1 member')
    })

    it('formats add with multiple members', () => {
      const body = JSON.stringify({
        added_at: 1710000000,
        new_members: [
          { key_id: 'c3d4', public_key: 'pk2', role: 'member', added_at: 1710000000, added_by: 'a1b2' },
          { key_id: 'e5f6', public_key: 'pk3', role: 'member', added_at: 1710000000, added_by: 'a1b2' },
        ],
      })
      const result = formatGroupEvent('group_add', body, 'Alice')
      expect(result!.headline).toContain('2 members')
    })
  })

  describe('group_remove', () => {
    it('formats remove with member count', () => {
      const body = JSON.stringify({
        removed_at: 1710000000,
        removed_members: ['c3d4'],
        reason: 'violated policy',
      })
      const result = formatGroupEvent('group_remove', body, 'Alice')
      expect(result).not.toBeNull()
      expect(result!.icon).toBe('remove')
      expect(result!.headline).toContain('Alice')
      expect(result!.headline).toContain('removed')
      expect(result!.headline).toContain('1 member')
    })

    it('includes reason when provided', () => {
      const body = JSON.stringify({
        removed_at: 1710000000,
        removed_members: ['c3d4'],
        reason: 'violated policy',
      })
      const result = formatGroupEvent('group_remove', body, 'Alice')
      expect(result!.detail).toContain('violated policy')
    })

    it('omits reason detail when empty', () => {
      const body = JSON.stringify({
        removed_at: 1710000000,
        removed_members: ['c3d4'],
        reason: '',
      })
      const result = formatGroupEvent('group_remove', body, 'Alice')
      expect(result!.detail).toBe('')
    })
  })

  describe('group_rekey', () => {
    it('formats rekey with epoch number', () => {
      const body = JSON.stringify({
        new_conv_epoch: 3,
        wrapped_keys: { kid1: 'blob1', kid2: 'blob2' },
      })
      const result = formatGroupEvent('group_rekey', body)
      expect(result).not.toBeNull()
      expect(result!.icon).toBe('rekey')
      expect(result!.headline).toContain('Security keys rotated')
      expect(result!.detail).toContain('epoch 3')
    })
  })

  it('returns null for unknown body types', () => {
    expect(formatGroupEvent('text', '{}')).toBeNull()
    expect(formatGroupEvent('gate.request', '{}')).toBeNull()
  })

  it('returns null for unparseable body', () => {
    expect(formatGroupEvent('group_genesis', 'not json')).toBeNull()
  })
})

describe('formatGovEvent', () => {
  it('formats floor_change proposal', () => {
    const body = JSON.stringify({
      proposal_type: 'floor_change',
      proposed_floor: 3,
      required_approvals: 2,
    })
    const result = formatGovEvent('gov.propose', body, 'Alice')
    expect(result).not.toBeNull()
    expect(result!.headline).toContain('Alice')
    expect(result!.headline).toContain('floor to 3')
    expect(result!.detail).toContain('2 approvals')
  })

  it('formats rules_change proposal', () => {
    const body = JSON.stringify({
      proposal_type: 'rules_change',
      proposed_rules: [{ service: 'api', endpoint: '/v1', verb: 'POST', m: 2 }],
      required_approvals: 1,
    })
    const result = formatGovEvent('gov.propose', body, 'Bob')
    expect(result!.headline).toContain('policy rules')
  })

  it('formats gov.approve', () => {
    const body = JSON.stringify({ proposal_id: 'prop-12345678abcd' })
    const result = formatGovEvent('gov.approve', body, 'Alice')
    expect(result!.headline).toContain('Alice')
    expect(result!.headline).toContain('approved')
  })

  it('formats gov.disapprove', () => {
    const body = JSON.stringify({ proposal_id: 'prop-12345678abcd' })
    const result = formatGovEvent('gov.disapprove', body, 'Bob')
    expect(result!.headline).toContain('rejected')
  })

  it('formats gov.applied for floor change', () => {
    const body = JSON.stringify({
      proposal_type: 'floor_change',
      applied_floor: 3,
    })
    const result = formatGovEvent('gov.applied', body)
    expect(result!.headline).toContain('Floor changed to 3')
  })

  it('formats gov.applied for rules change', () => {
    const body = JSON.stringify({
      proposal_type: 'rules_change',
      applied_rules: [{ service: 'api', endpoint: '/v1', verb: 'POST', m: 2 }],
    })
    const result = formatGovEvent('gov.applied', body)
    expect(result!.headline).toContain('Policy rules updated')
  })

  it('formats member_add proposal', () => {
    const body = JSON.stringify({
      proposal_type: 'member_add',
      proposed_members: [{ kid: 'kid1', public_key: 'pk1' }],
      required_approvals: 2,
    })
    const result = formatGovEvent('gov.propose', body, 'Alice')
    expect(result!.headline).toContain('adding 1 member')
  })

  it('formats member_remove proposal', () => {
    const body = JSON.stringify({
      proposal_type: 'member_remove',
      removed_member_kids: ['kid1', 'kid2'],
      required_approvals: 2,
    })
    const result = formatGovEvent('gov.propose', body, 'Alice')
    expect(result!.headline).toContain('removing 2 members')
  })

  it('formats gov.applied for member_add', () => {
    const body = JSON.stringify({
      proposal_type: 'member_add',
      applied_members: [{ kid: 'kid1', public_key: 'pk1' }],
    })
    const result = formatGovEvent('gov.applied', body)
    expect(result!.headline).toContain('1 member added')
  })

  it('formats gov.applied for member_remove', () => {
    const body = JSON.stringify({
      proposal_type: 'member_remove',
      removed_member_kids: ['kid1'],
    })
    const result = formatGovEvent('gov.applied', body)
    expect(result!.headline).toContain('1 member removed')
  })

  it('returns null for unknown types', () => {
    expect(formatGovEvent('text', '{}')).toBeNull()
    expect(formatGovEvent('gate.request', '{}')).toBeNull()
  })
})
