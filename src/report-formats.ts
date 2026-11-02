import { AnalysisReport, AnalyzedPackage, VulnerabilityFinding } from './types.js';

type ReportFormat = 'sarif' | 'cyclonedx' | 'spdx' | 'markdown' | 'html';

function packageUrl(pkg: Pick<AnalyzedPackage, 'ecosystem' | 'name' | 'version'>): string {
  const name = pkg.ecosystem === 'npm' && pkg.name.startsWith('@')
    ? `%40${pkg.name.slice(1).split('/').map(encodeURIComponent).join('/')}`
    : encodeURIComponent(pkg.name);
  return `pkg:${pkg.ecosystem === 'pypi' ? 'pypi' : 'npm'}/${name}@${encodeURIComponent(pkg.version)}`;
}

function findingRef(pkg: AnalyzedPackage): string {
  return packageUrl(pkg);
}

function severityName(severity: VulnerabilityFinding['severityLevel']): string {
  switch (severity) {
    case 'CRITICAL': return 'critical';
    case 'HIGH': return 'high';
    case 'MODERATE': return 'medium';
    case 'LOW': return 'low';
    default: return 'unknown';
  }
}

function sarifLevel(severity: VulnerabilityFinding['severityLevel']): string {
  switch (severity) {
    case 'CRITICAL':
    case 'HIGH': return 'error';
    case 'MODERATE': return 'warning';
    case 'LOW': return 'note';
    default: return 'none';
  }
}

function htmlEscape(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[character]!);
}

function markdownEscape(value: string): string {
  return value.replace(/[\\`*_{}[\]()#+.!|><-]/g, '\\$&');
}

function findingsFor(report: AnalysisReport): Array<{
  pkg: AnalyzedPackage;
  finding: VulnerabilityFinding;
}> {
  return report.packages.flatMap((pkg) =>
    pkg.vulnerabilities.map((finding) => ({ pkg, finding }))
  );
}

export function toCycloneDx(report: AnalysisReport): Record<string, unknown> {
  const components = new Map<string, Record<string, unknown>>();
  for (const pkg of report.packages) {
    const ref = packageUrl(pkg);
    if (!components.has(ref)) {
      components.set(ref, {
        type: 'library',
        'bom-ref': ref,
        name: pkg.name,
        version: pkg.version,
        purl: ref,
        properties: [
          { name: 'veylix:ecosystem', value: pkg.ecosystem },
          { name: 'veylix:is-direct', value: String(pkg.isDirect) },
          { name: 'veylix:is-development', value: String(pkg.isDev) }
        ]
      });
    }
  }

  const vulnerabilities = findingsFor(report).map(({ pkg, finding }) => {
    const reference = `https://osv.dev/vulnerability/${encodeURIComponent(finding.advisoryId)}`;
    return {
      id: finding.advisoryId,
      source: { name: 'OSV', url: reference },
      ratings: [{
        source: { name: 'OSV' },
        severity: severityName(finding.severityLevel),
        method: 'other'
      }],
      ...(finding.summary ? { description: finding.summary } : {}),
      ...(finding.actionableRecommendation ? { recommendation: finding.actionableRecommendation } : {}),
      advisories: [{ url: reference }],
      affects: [{ ref: findingRef(pkg), versions: [{ version: pkg.version, status: 'affected' }] }],
      properties: [
        { name: 'veylix:ecosystem', value: pkg.ecosystem },
        { name: 'veylix:package-name', value: pkg.name },
        ...(finding.fixedVersion ? [{ name: 'veylix:fixed-version', value: finding.fixedVersion }] : [])
      ]
    };
  });

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: {
      timestamp: report.summary.timestamp,
      tools: [{ vendor: 'Veylix', name: 'Veylix Dependency Scanner' }]
    },
    components: Array.from(components.values()),
    vulnerabilities
  };
}

function spdxIdFor(index: number, pkg: AnalyzedPackage): string {
  const slug = `${pkg.name}-${pkg.version}`.replace(/[^A-Za-z0-9.-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);
  return `SPDXRef-Package-${slug || 'dependency'}-${index + 1}`;
}

export function toSpdx(report: AnalysisReport): Record<string, unknown> {
  const packageEntries = new Map<string, { id: string; pkg: AnalyzedPackage }>();
  for (const pkg of report.packages) {
    const ref = packageUrl(pkg);
    if (!packageEntries.has(ref)) {
      packageEntries.set(ref, { id: spdxIdFor(packageEntries.size, pkg), pkg });
    }
  }

  const packages = Array.from(packageEntries.values()).map(({ id, pkg }) => {
    const securityRefs = pkg.vulnerabilities.map((finding) => ({
      referenceCategory: 'SECURITY',
      referenceType: 'advisory',
      referenceLocator: `https://osv.dev/vulnerability/${encodeURIComponent(finding.advisoryId)}`,
      comment: `${finding.severityLevel}: ${finding.summary}`
    }));
    return {
      name: pkg.name,
      SPDXID: id,
      versionInfo: pkg.version,
      downloadLocation: 'NOASSERTION',
      filesAnalyzed: false,
      licenseConcluded: 'NOASSERTION',
      licenseDeclared: 'NOASSERTION',
      copyrightText: 'NOASSERTION',
      primaryPackagePurpose: 'LIBRARY',
      externalRefs: [
        {
          referenceCategory: 'PACKAGE-MANAGER',
          referenceType: 'purl',
          referenceLocator: packageUrl(pkg)
        },
        ...securityRefs
      ]
    };
  });

  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `Veylix ${report.summary.ecosystem} dependency scan`,
    documentNamespace: `https://veylix.local/spdx/${encodeURIComponent(report.summary.timestamp)}/${report.summary.ecosystem}`,
    creationInfo: {
      created: report.summary.timestamp,
      creators: ['Tool: Veylix']
    },
    packages,
    relationships: Array.from(packageEntries.values()).map(({ id }) => ({
      spdxElementId: 'SPDXRef-DOCUMENT',
      relationshipType: 'DESCRIBES',
      relatedSpdxElement: id
    }))
  };
}

export function toSarif(report: AnalysisReport): Record<string, unknown> {
  const findings = findingsFor(report);
  const ruleMap = new Map<string, VulnerabilityFinding>();
  for (const { finding } of findings) {
    if (!ruleMap.has(finding.advisoryId)) ruleMap.set(finding.advisoryId, finding);
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'Veylix',
          rules: Array.from(ruleMap.entries()).map(([id, finding]) => ({
            id,
            shortDescription: { text: finding.summary || id },
            defaultConfiguration: { level: sarifLevel(finding.severityLevel) },
            helpUri: `https://osv.dev/vulnerability/${encodeURIComponent(id)}`
          }))
        }
      },
      results: findings.map(({ pkg, finding }) => ({
        ruleId: finding.advisoryId,
        level: sarifLevel(finding.severityLevel),
        message: { text: `${pkg.name}@${pkg.version}: ${finding.summary}` },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: report.summary.manifestType }
          }
        }],
        properties: {
          packageName: pkg.name,
          packageVersion: pkg.version,
          ecosystem: pkg.ecosystem,
          isDirect: pkg.isDirect,
          ...(finding.fixedVersion ? { fixedVersion: finding.fixedVersion } : {})
        }
      }))
    }]
  };
}

export function toMarkdownReport(report: AnalysisReport): string {
  const lines = [
    '# Veylix Dependency Scan',
    '',
    `- Ecosystem: ${report.summary.ecosystem}`,
    `- Manifest: ${report.summary.manifestType}`,
    `- Scanned: ${report.summary.timestamp}`,
    `- Dependencies: ${report.summary.totalDependenciesResolved}`,
    `- Vulnerability findings: ${report.summary.totalAdvisoriesCount}`,
    '',
    '## Findings',
    ''
  ];

  const findings = findingsFor(report);
  if (findings.length === 0) lines.push('No vulnerability findings were returned by OSV.');
  for (const { pkg, finding } of findings) {
    lines.push(
      `- **${markdownEscape(finding.severityLevel)}** ${markdownEscape(pkg.name)}@${markdownEscape(pkg.version)} — ` +
      `${markdownEscape(finding.advisoryId)}: ${markdownEscape(finding.summary)}` +
      (finding.fixedVersion ? ` (fixed version: ${markdownEscape(finding.fixedVersion)})` : '')
    );
  }
  if (report.warnings.length > 0) {
    lines.push('', '## Scan warnings', '', ...report.warnings.map((warning) => `- ${markdownEscape(warning)}`));
  }
  lines.push('');
  return lines.join('\n');
}

export function toHtmlReport(report: AnalysisReport): string {
  const rows = findingsFor(report).map(({ pkg, finding }) => `
    <tr>
      <td>${htmlEscape(finding.severityLevel)}</td>
      <td>${htmlEscape(pkg.name)}@${htmlEscape(pkg.version)}</td>
      <td><a href="https://osv.dev/vulnerability/${encodeURIComponent(finding.advisoryId)}" rel="noopener noreferrer">${htmlEscape(finding.advisoryId)}</a></td>
      <td>${htmlEscape(finding.summary)}</td>
      <td>${htmlEscape(finding.fixedVersion ?? 'No fixed version recorded')}</td>
    </tr>`).join('');
  const warnings = report.warnings.map((warning) => `<li>${htmlEscape(warning)}</li>`).join('');
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Veylix Dependency Scan</title>
  <style>
    :root { color-scheme: light; font-family: system-ui, sans-serif; color: #172033; background: #f7f9fc; }
    body { margin: 0 auto; max-width: 1100px; padding: 2rem 1rem; }
    h1 { margin-bottom: .3rem; } .meta { color: #536078; }
    table { width: 100%; border-collapse: collapse; background: white; }
    th, td { padding: .7rem; border: 1px solid #dce2eb; text-align: left; vertical-align: top; }
    th { background: #eef2f8; } a { color: #135bb8; } .warning { border-left: 4px solid #bd7900; padding-left: 1rem; }
    @media (max-width: 640px) { body { padding: 1rem .5rem; } th, td { padding: .4rem; overflow-wrap: anywhere; } }
    @media print { body { max-width: none; } }
  </style>
</head>
<body>
  <h1>Veylix Dependency Scan</h1>
  <p class="meta">${htmlEscape(report.summary.ecosystem)} · ${htmlEscape(report.summary.manifestType)} · ${htmlEscape(report.summary.timestamp)}</p>
  <p>${report.summary.totalDependenciesResolved} dependencies · ${report.summary.totalAdvisoriesCount} vulnerability findings</p>
  <h2>Findings</h2>
  ${rows
    ? `<div style="overflow-x:auto"><table><thead><tr><th>Severity</th><th>Package</th><th>Advisory</th><th>Summary</th><th>Fixed version</th></tr></thead><tbody>${rows}</tbody></table></div>`
    : '<p>No vulnerability findings were returned by OSV.</p>'}
  ${warnings ? `<section class="warning"><h2>Scan warnings</h2><ul>${warnings}</ul></section>` : ''}
</body>
</html>`;
}

export function serializeReportFormat(report: AnalysisReport, format: ReportFormat): string {
  switch (format) {
    case 'sarif': return JSON.stringify(toSarif(report), null, 2);
    case 'cyclonedx': return JSON.stringify(toCycloneDx(report), null, 2);
    case 'spdx': return JSON.stringify(toSpdx(report), null, 2);
    case 'markdown': return toMarkdownReport(report);
    case 'html': return toHtmlReport(report);
  }
}
