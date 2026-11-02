import { describe, expect, it } from 'vitest';
import { AnalysisReport } from '../src/types.js';
import { serializeReportFormat, toCycloneDx, toHtmlReport, toMarkdownReport, toSarif, toSpdx } from '../src/report-formats.js';

const sampleReport: AnalysisReport = {
  summary: {
    manifestType: 'package-lock.json',
    ecosystem: 'npm',
    totalUniquePackages: 1,
    totalDependenciesResolved: 1,
    directDependenciesCount: 1,
    vulnerablePackagesCount: 1,
    totalAdvisoriesCount: 1,
    severityCounts: { critical: 0, high: 1, moderate: 0, low: 0, unknown: 0 },
    scanDurationMs: 30,
    timestamp: '2024-06-01T00:00:00.000Z'
  },
  packages: [{
    name: '@scope/pkg',
    version: '1.2.3',
    ecosystem: 'npm',
    isDirect: true,
    isDev: false,
    dependencyPaths: ['@scope/pkg@1.2.3'],
    hasVulnerability: true,
    vulnerabilities: [{
      advisoryId: 'GHSA-test-1234',
      aliases: ['CVE-2024-12345'],
      severityLevel: 'HIGH',
      summary: '<script>alert("x")</script>',
      fixedVersion: '1.2.4',
      actionableRecommendation: 'Upgrade to 1.2.4.'
    }]
  }],
  vulnerablePackages: [],
  maintenanceRiskPackages: [],
  warnings: ['Warning with <tag> content']
};
sampleReport.vulnerablePackages = sampleReport.packages;

describe('Report format serializers', () => {
  it('creates CycloneDX 1.5 components and affected vulnerability references', () => {
    const bom = toCycloneDx(sampleReport) as {
      bomFormat: string;
      specVersion: string;
      components: Array<{ purl: string; properties: Array<{ name: string; value: string }> }>;
      vulnerabilities: Array<{ id: string; affects: Array<{ ref: string; versions: Array<{ status: string }> }> }>;
    };

    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.5');
    expect(bom.components[0]?.purl).toBe('pkg:npm/%40scope/pkg@1.2.3');
    expect(bom.components[0]?.properties).toContainEqual({ name: 'veylix:is-direct', value: 'true' });
    expect(bom.vulnerabilities[0]).toMatchObject({
      id: 'GHSA-test-1234',
      affects: [{ ref: 'pkg:npm/%40scope/pkg@1.2.3', versions: [{ status: 'affected' }] }]
    });
  });

  it('creates SPDX 2.3 package references and advisory references', () => {
    const spdx = toSpdx(sampleReport) as {
      spdxVersion: string;
      dataLicense: string;
      packages: Array<{ SPDXID: string; externalRefs: Array<{ referenceCategory: string; referenceLocator: string }> }>;
      relationships: Array<{ relationshipType: string; relatedSpdxElement: string }>;
    };

    expect(spdx.spdxVersion).toBe('SPDX-2.3');
    expect(spdx.dataLicense).toBe('CC0-1.0');
    expect(spdx.packages[0]?.externalRefs).toContainEqual(expect.objectContaining({
      referenceCategory: 'PACKAGE-MANAGER',
      referenceLocator: 'pkg:npm/%40scope/pkg@1.2.3'
    }));
    expect(spdx.packages[0]?.externalRefs).toContainEqual(expect.objectContaining({
      referenceCategory: 'SECURITY',
      referenceLocator: 'https://osv.dev/vulnerability/GHSA-test-1234'
    }));
    expect(spdx.relationships[0]?.relatedSpdxElement).toBe(spdx.packages[0]?.SPDXID);
  });

  it('creates SARIF 2.1.0 results with severity and package metadata but no fabricated line number', () => {
    const sarif = toSarif(sampleReport) as {
      version: string;
      runs: Array<{
        tool: { driver: { rules: Array<{ id: string }> } };
        results: Array<{
          level: string;
          ruleId: string;
          locations: Array<{ physicalLocation: { artifactLocation: { uri: string }; region?: unknown } }>;
          properties: { packageName: string; packageVersion: string };
        }>;
      }>;
    };
    const result = sarif.runs[0]?.results[0];

    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]?.tool.driver.rules[0]?.id).toBe('GHSA-test-1234');
    expect(result).toMatchObject({
      ruleId: 'GHSA-test-1234',
      level: 'error',
      properties: { packageName: '@scope/pkg', packageVersion: '1.2.3' },
      locations: [{ physicalLocation: { artifactLocation: { uri: 'package-lock.json' } } }]
    });
    expect(result?.locations[0]?.physicalLocation.region).toBeUndefined();
  });

  it('escapes untrusted finding and warning text in HTML and Markdown', () => {
    const html = toHtmlReport(sampleReport);
    const markdown = toMarkdownReport(sampleReport);

    expect(html).toContain('&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;');
    expect(html).toContain('Warning with &lt;tag&gt; content');
    expect(html).not.toContain('<script>alert');
    expect(markdown).toContain('\\<script\\>');
    expect(markdown).toContain('\\<tag\\>');
  });

  it('serializes every format to its expected content type shape', () => {
    expect(JSON.parse(serializeReportFormat(sampleReport, 'sarif'))).toMatchObject({ version: '2.1.0' });
    expect(JSON.parse(serializeReportFormat(sampleReport, 'cyclonedx'))).toMatchObject({ bomFormat: 'CycloneDX' });
    expect(JSON.parse(serializeReportFormat(sampleReport, 'spdx'))).toMatchObject({ spdxVersion: 'SPDX-2.3' });
    expect(serializeReportFormat(sampleReport, 'markdown')).toContain('# Veylix Dependency Scan');
    expect(serializeReportFormat(sampleReport, 'html')).toContain('<!doctype html>');
  });
});
