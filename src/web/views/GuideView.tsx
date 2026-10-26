import React from 'react';
import { ActiveTab } from '../types.js';

interface GuideViewProps {
  page: Extract<ActiveTab, 'faq' | 'documentation'>;
}

const faqItems = [
  {
    question: 'How do I scan a project?',
    answer: 'Open New Scan, then upload supported dependency files or enter a public GitHub repository reference. Local-file scans need package-lock.json for npm; package.json is companion metadata only. Python scans accept requirements.txt or poetry.lock, with pyproject.toml optional for Poetry.'
  },
  {
    question: 'Which ecosystems and file formats are supported?',
    answer: 'Veylix supports npm package-lock.json lockfile versions 1 through 3, Python requirements.txt, and Poetry poetry.lock. A package.json or pyproject.toml may supply additional direct-dependency metadata where available.'
  },
  {
    question: 'How are vulnerability findings and severity determined?',
    answer: 'The existing parser extracts package names and versions, then the engine queries the OSV batch API. Findings and severity come from the returned advisory data and its severity/CVSS fields. A scan can only report matching records present in upstream data at that time.'
  },
  {
    question: 'What does a fixed version mean?',
    answer: 'A fixed version is derived from the advisory’s affected-range events for the matching package and ecosystem. It is an advisory-based upgrade target, not a compatibility guarantee. Review the advisory and test the exact suggested version in your project.'
  },
  {
    question: 'What if no verified fix is shown?',
    answer: 'The returned advisory data did not provide a usable fixed version for the affected package. Veylix does not substitute the latest published package version or guess an upgrade. Review the upstream advisory and consider its documented mitigations.'
  },
  {
    question: 'Where is scan history stored?',
    answer: 'Saved reports are kept in this browser’s localStorage, up to 25 entries. History and comparisons are not sent to Veylix or synchronized across devices, and can be removed from Scan History or Settings. Browser storage may be cleared or unavailable.'
  },
  {
    question: 'What do incomplete scans or warnings mean?',
    answer: 'A parser warning can indicate skipped or approximate input, such as an unpinned Python requirement. A required OSV lookup failure fails the scan rather than being reported as zero findings. An empty advisory result is not proof that dependencies are safe.'
  },
  {
    question: 'What data is sent to external services?',
    answer: 'The scan API or browser fallback processes manifest contents to extract dependency identifiers. Package names and versions are sent to OSV; optional maintenance checks use deps.dev. Public GitHub scans fetch supported manifests from GitHub raw content. Do not submit secrets, private repository URLs, or files you are not authorized to scan.'
  },
  {
    question: 'Can I use Veylix in CI?',
    answer: 'The local CLI accepts a file or project directory, ecosystem, output format, and severity threshold. It exits 0 when the threshold is not met, 1 when it is met, and 2 for invalid input or scan failure. The included GitHub Actions workflow is an example for the repository containing this CLI; adapt it only with a trusted, pinned Veylix source.'
  }
];

export const GuideView: React.FC<GuideViewProps> = ({ page }) => {
  const isFaq = page === 'faq';

  return (
    <article className="guide-page animate-in">
      <p className="overview-eyebrow">Veylix · {isFaq ? 'Frequently asked questions' : 'User guide'}</p>
      <h1>{isFaq ? 'FAQ' : 'Documentation'}</h1>
      <p className="guide-intro">
        {isFaq
          ? 'Answers about supported scans, advisory data, privacy, and limitations.'
          : 'How to run scans, interpret results, use local history, and automate checks.'}
      </p>

      {isFaq ? (
        <div className="guide-sections">
          {faqItems.map(({ question, answer }) => (
            <details className="guide-faq-item" key={question}>
              <summary>{question}</summary>
              <p>{answer}</p>
            </details>
          ))}
        </div>
      ) : (
        <div className="guide-sections">
          <section>
            <h2>Scan a project</h2>
            <ol>
              <li>Choose <a href="/new-scan">New Scan</a> and upload one supported lockfile, or submit a public GitHub repository reference.</li>
              <li>For npm, include package-lock.json; package.json may be supplied as companion metadata. For Python, use requirements.txt or poetry.lock.</li>
              <li>Review parser warnings, findings, affected ranges, advisory links, and any verified fixed version. Veylix does not edit manifests or run upgrade commands.</li>
            </ol>
          </section>
          <section>
            <h2>How scanning works</h2>
            <p>The existing TypeScript engine parses supported manifests and queries OSV using package names, ecosystems, and resolved or parser-derived versions. Optional maintenance checks query deps.dev. Public GitHub scans fetch supported manifests; Veylix does not clone or execute repository code.</p>
            <p>Dependency relationships are shown only when lockfile paths contain exact package names and versions that can be matched unambiguously. Other parser formats may provide inventory and direct/transitive labels without a provable parent-child graph; those relationships are not inferred.</p>
          </section>
          <section>
            <h2>Local CLI</h2>
            <p>From a Veylix checkout with Node.js 20 or newer and dependencies installed, run:</p>
            <pre><code>node ./bin/veylix.js scan --file ./package-lock.json --ecosystem npm --threshold high --format json</code></pre>
            <p>Supported inputs include package-lock.json, package.json with an adjacent lockfile, requirements.txt, poetry.lock, or a directory containing a supported manifest. JSON output is intended for automation. Exit code 0 means the threshold was not reached, 1 means a finding met it, and 2 means invalid input or scan execution failure.</p>
          </section>
          <section>
            <h2>GitHub Actions</h2>
            <p>The repository’s <code>.github/workflows/veylix.yml</code> demonstrates a local CLI scan with minimum read-only repository permissions, SHA-pinned GitHub Actions, and a JSON artifact. The CLI makes upstream lookups to OSV (and deps.dev only when maintenance enrichment is enabled); it does not send a manifest to a Veylix-hosted scan API. For other repositories, use a trusted pinned copy or distribution of the CLI rather than an unpinned source.</p>
          </section>
          <section>
            <h2>Privacy and limitations</h2>
            <p>Reports and scan comparisons are stored/calculated in this browser only. The server does not intentionally retain scan reports. Package identifiers are sent to upstream advisory services to perform lookups; hosting providers may process operational request metadata. See the <a href="/privacy">Privacy Policy</a> for further details.</p>
            <p>Coverage depends on parsed files and upstream advisory data. Python ranges may be analyzed using a base version and carry a warning. A missing advisory is not proof of safety, and upgrade compatibility is not tested by Veylix.</p>
          </section>
        </div>
      )}

      <nav className="guide-related-links" aria-label="Related information">
        {isFaq
          ? <a href="/documentation">Read the documentation</a>
          : <a href="/faq">Browse frequently asked questions</a>}
        <a href="/privacy">Privacy Policy</a>
      </nav>
    </article>
  );
};
