import { IVulnerability } from '../models/Vulnerability';

export interface IDriftComparisonResult {
  previousScore: number;
  currentScore: number;
  difference: number;
  resolvedCount: number;
  newCount: number;
  severityChanges: {
    issue: string;
    endpoint: string;
    from: string;
    to: string;
  }[];
}

/**
 * Compares current scan findings against previous scan findings to calculate deltas.
 */
export function calculateDrift(
  previousScore: number,
  currentScore: number,
  previousFindings: IVulnerability[],
  currentFindings: IVulnerability[]
): IDriftComparisonResult {
  const previousMap = new Map<string, IVulnerability>();
  previousFindings.forEach((f) => {
    if (f.findingId) {
      previousMap.set(f.findingId, f);
    }
  });

  const currentMap = new Map<string, IVulnerability>();
  currentFindings.forEach((f) => {
    if (f.findingId) {
      currentMap.set(f.findingId, f);
    }
  });

  let resolvedCount = 0;
  let newCount = 0;
  const severityChanges: {
    issue: string;
    endpoint: string;
    from: string;
    to: string;
  }[] = [];

  // 1. Detect resolved findings (existed as findings in previous, but now missing or passed)
  previousFindings.forEach((pf) => {
    if (pf.findingId && (pf.category === 'Security Findings' || pf.category === 'Observations')) {
      const cf = currentMap.get(pf.findingId);
      if (!cf || cf.category === 'Passed Checks') {
        resolvedCount++;
      }
    }
  });

  // 2. Detect new findings (exist in current, but didn't exist as active findings previously)
  currentFindings.forEach((cf) => {
    if (cf.findingId && (cf.category === 'Security Findings' || cf.category === 'Observations')) {
      const pf = previousMap.get(cf.findingId);
      if (!pf || (pf.category !== 'Security Findings' && pf.category !== 'Observations')) {
        newCount++;
      }
    }
  });

  // 3. Detect severity changes for findings present in both runs
  currentFindings.forEach((cf) => {
    if (cf.findingId) {
      const pf = previousMap.get(cf.findingId);
      if (pf && pf.severity !== cf.severity) {
        severityChanges.push({
          issue: cf.issue,
          endpoint: cf.endpoint,
          from: pf.severity,
          to: cf.severity,
        });
      }
    }
  });

  return {
    previousScore,
    currentScore,
    difference: currentScore - previousScore,
    resolvedCount,
    newCount,
    severityChanges,
  };
}
