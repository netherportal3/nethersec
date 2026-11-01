import { describe, expect, it } from 'vitest'
import { reportKey, stripControls, validateReport } from '../src/reports/protocol.js'

const base = { kind: 'security', source: 'web1', event: 'ssh-auth-burst' }

describe('validateReport', () => {
  it('accepts a minimal report and applies the defaults', () => {
    const v = validateReport(base)
    expect(v).toEqual({
      ok: true,
      report: { kind: 'security', source: 'web1', event: 'ssh-auth-burst', state: 'triggered', severity: 'warning', title: '', detail: '', group: '', data: false },
    })
    const up = validateReport({ ...base, kind: 'uptime', severity: '' })
    expect(up.ok && up.report.severity).toBe('critical')
  })

  // [what, body, the field the 400 names]
  const table: Array<[string, unknown, string]> = [
    ['not an object', [base], 'body'],
    ['null', null, 'body'],
    ['v other than 1', { ...base, v: 2 }, 'v'],
    ['v as a string', { ...base, v: '1' }, 'v'],
    ['no kind', { source: 'web1', event: 'x' }, 'kind'],
    ['an unknown kind', { ...base, kind: 'status' }, 'kind'],
    ['no source', { kind: 'security', event: 'x' }, 'source'],
    ['an uppercase source', { ...base, source: 'Web1' }, 'source'],
    ['a source with a dot', { ...base, source: 'web1.example.com' }, 'source'],
    ['a source over 40 characters', { ...base, source: 'a'.repeat(41) }, 'source'],
    ['a source starting with a dash', { ...base, source: '-web1' }, 'source'],
    ['no event', { kind: 'security', source: 'web1' }, 'event'],
    ['an event with a space', { ...base, event: 'ssh burst' }, 'event'],
    ['an event over 64 characters', { ...base, event: 'e'.repeat(65) }, 'event'],
    ['a state other than triggered or resolved', { ...base, state: 'down' }, 'state'],
    ['an unknown severity', { ...base, severity: 'high' }, 'severity'],
    ['a number for a string field', { ...base, title: 5 }, 'title'],
    ['a title over 120 characters', { ...base, title: 't'.repeat(121) }, 'title'],
    ['a detail over 1,500 characters', { ...base, detail: 'd'.repeat(1501) }, 'detail'],
    ['a group over 40 characters', { ...base, group: 'g'.repeat(41) }, 'group'],
  ]
  for (const [what, body, field] of table) {
    it(`refuses ${what} (field ${field})`, () => {
      const v = validateReport(body)
      expect(v.ok).toBe(false)
      if (!v.ok) expect(v.field).toBe(field)
    })
  }

  it('takes the limits exactly, counting characters, not bytes', () => {
    expect(validateReport({ ...base, title: 't'.repeat(120), detail: 'd'.repeat(1500), group: 'g'.repeat(40), source: 'a'.repeat(40), event: 'e'.repeat(64) }).ok).toBe(true)
    // 120 characters that are 3 bytes each in UTF-8.
    expect(validateReport({ ...base, title: String.fromCodePoint(0x4e00).repeat(120) }).ok).toBe(true)
  })

  it('gives the two data events room for their lists, and only for kind security', () => {
    const long = 'x'.repeat(10_000)
    expect(validateReport({ ...base, event: 'container-packages', detail: long })).toMatchObject({ ok: true, report: { data: true } })
    expect(validateReport({ ...base, event: 'reboot-pending', detail: long })).toMatchObject({ ok: true, report: { data: true } })
    expect(validateReport({ ...base, event: 'reboot-pending', detail: 'x'.repeat(64_001) })).toMatchObject({ ok: false, field: 'detail' })
    expect(validateReport({ ...base, kind: 'uptime', event: 'reboot-pending', detail: long })).toMatchObject({ ok: false, field: 'detail' })
    expect(validateReport({ ...base, kind: 'uptime', event: 'reboot-pending' })).toMatchObject({ ok: true, report: { data: false } })
  })

  it('ignores unknown fields and an empty state', () => {
    expect(validateReport({ ...base, state: '', host: 'x', extra: { a: 1 } }).ok).toBe(true)
  })

  it('strips control characters and bidirectional overrides, keeping words apart', () => {
    const bidi = String.fromCharCode(0x202e)
    const v = validateReport({ ...base, title: `bad${String.fromCharCode(0)}\tname${bidi}`, detail: 'line one\nline two\r\n' })
    expect(v.ok && v.report.title).toBe('bad name')
    expect(v.ok && v.report.detail).toBe('line one line two')
    expect(stripControls(`a${String.fromCharCode(0x7f)}b${String.fromCharCode(0x9b)}c`)).toBe('abc')
  })

  it('names a report by kind, source and event', () => {
    expect(reportKey({ kind: 'uptime', source: 'db1', event: 'disk' })).toBe('uptime:db1:disk')
  })
})
