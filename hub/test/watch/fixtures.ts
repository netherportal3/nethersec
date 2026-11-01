/** Small inline fixtures in the shapes the real feeds use. */

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

/** One RSS item shaped like a security bulletin: a short "Published" line, then the description. */
export function rssItem(id: string, publishedMs: number, firstPara: string, body: string, categories: string[] = []): string {
  return `<item>
    <title>${id}</title>
    <link>https://example.com/bulletins/#${id.toLowerCase()}</link>
    <guid>https://example.com/bulletins/#${id.toLowerCase()}</guid>
    <pubDate>${new Date(publishedMs).toUTCString()}</pubDate>
    ${categories.map((c) => `<category>${c}</category>`).join('')}
    <description>${esc(`<p>Published: today</p><p><strong>Description</strong>: ${firstPara}</p>\n<p>${body}</p>`)}</description>
  </item>`
}

export function rss(...items: string[]): string {
  return `<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0"><channel><title>Bulletins</title>${items.join('\n')}</channel></rss>`
}

export function ghAdvisory(id: string, severity: string, publishedMs: number, extra: Record<string, unknown> = {}) {
  return {
    ghsa_id: id,
    html_url: `https://github.com/example/engine/security/advisories/${id}`,
    summary: `Summary of ${id}`,
    severity,
    state: 'published',
    published_at: new Date(publishedMs).toISOString(),
    withdrawn_at: null,
    vulnerabilities: [{ patched_versions: '2.0.1' }],
    ...extra,
  }
}

/** One catalog entry in CISA's KEV shape. */
export function kevEntry(cveID: string, vendorProject: string, product: string, dateAdded = '2025-03-26', extra: Record<string, string> = {}) {
  return {
    cveID,
    vendorProject,
    product,
    vulnerabilityName: `${vendorProject} ${product} bug`,
    dateAdded,
    shortDescription: `${vendorProject} ${product} contains a flaw that lets a remote attacker run code.`,
    requiredAction: 'Apply mitigations per vendor instructions.',
    dueDate: '2025-04-16',
    knownRansomwareCampaignUse: 'Unknown',
    ...extra,
  }
}
