import { AnalysisReport, AnalyzedPackage } from '../../types.js';

const MAX_NODES = 500;
const MAX_EDGES = 2000;
const MAX_DEPTH = 30;
const MAX_PATHS = 100;
const MAX_PATH_SEARCH_STEPS = 10000;

export interface DependencyGraphNode {
  id: string;
  name: string;
  version: string;
  isDirect: boolean;
  isVulnerable: boolean;
}

export interface DependencyGraphEdge {
  from: string;
  to: string;
}

export interface DependencyGraph {
  nodes: DependencyGraphNode[];
  edges: DependencyGraphEdge[];
  vulnerablePaths: DependencyGraphNode[][];
  available: boolean;
  cycleDetected: boolean;
  truncated: boolean;
}

function nodeId(pkg: Pick<AnalyzedPackage, 'ecosystem' | 'name' | 'version'>): string {
  return `${pkg.ecosystem}:${pkg.name}@${pkg.version}`;
}

function parseVersionedPathSegment(segment: string): { name: string; version: string } | null {
  const at = segment.lastIndexOf('@');
  if (at <= 0 || at === segment.length - 1) return null;
  const name = segment.slice(0, at).trim();
  const version = segment.slice(at + 1).trim();
  if (!name || !version || /[\\\s>]/.test(name) || /[\s>]/.test(version)) return null;
  return { name, version };
}

function detectCycle(nodes: DependencyGraphNode[], edges: DependencyGraphEdge[]): boolean {
  const adjacency = new Map<string, string[]>();
  for (const node of nodes) adjacency.set(node.id, []);
  for (const edge of edges) adjacency.get(edge.from)?.push(edge.to);

  const visiting = new Set<string>();
  const visited = new Set<string>();
  const visit = (id: string): boolean => {
    if (visiting.has(id)) return true;
    if (visited.has(id)) return false;
    visiting.add(id);
    for (const child of adjacency.get(id) ?? []) {
      if (visit(child)) return true;
    }
    visiting.delete(id);
    visited.add(id);
    return false;
  };

  return nodes.some((node) => visit(node.id));
}

function findVulnerablePaths(
  nodes: DependencyGraphNode[],
  edges: DependencyGraphEdge[]
): { paths: DependencyGraphNode[][]; truncated: boolean } {
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const adjacency = new Map<string, string[]>();
  for (const node of nodes) adjacency.set(node.id, []);
  for (const edge of edges) adjacency.get(edge.from)?.push(edge.to);

  const paths: DependencyGraphNode[][] = [];
  let searchSteps = 0;
  let truncated = false;
  const visit = (id: string, path: string[]): void => {
    if (paths.length >= MAX_PATHS || searchSteps >= MAX_PATH_SEARCH_STEPS) {
      truncated = true;
      return;
    }
    if (path.length > MAX_DEPTH || path.includes(id)) return;
    searchSteps++;
    const currentPath = [...path, id];
    const node = nodeById.get(id);
    if (node?.isVulnerable && currentPath.length > 1) {
      paths.push(currentPath.map((pathId) => nodeById.get(pathId)!).filter(Boolean));
      return;
    }
    for (const childId of adjacency.get(id) ?? []) {
      visit(childId, currentPath);
      if (paths.length >= MAX_PATHS) return;
    }
  };

  for (const node of nodes) {
    if (node.isDirect) visit(node.id, []);
    if (paths.length >= MAX_PATHS || searchSteps >= MAX_PATH_SEARCH_STEPS) {
      truncated = true;
      break;
    }
  }
  return { paths, truncated };
}

export function buildDependencyGraph(report: AnalysisReport): DependencyGraph {
  const truncated = report.packages.length > MAX_NODES;
  const packages = report.packages.slice(0, MAX_NODES);
  const candidates = new Map<string, AnalyzedPackage[]>();
  for (const pkg of packages) {
    const key = `${pkg.ecosystem}:${pkg.name}@${pkg.version}`;
    candidates.set(key, [...(candidates.get(key) ?? []), pkg]);
  }

  const nodes = packages.map((pkg) => ({
    id: nodeId(pkg),
    name: pkg.name,
    version: pkg.version,
    isDirect: pkg.isDirect,
    isVulnerable: pkg.hasVulnerability
  }));
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const edges: DependencyGraphEdge[] = [];
  const edgeKeys = new Set<string>();
  let wasTruncated = truncated;

  for (const pkg of packages) {
    const paths = Array.isArray(pkg.dependencyPaths) ? pkg.dependencyPaths.slice(0, MAX_PATHS) : [];
    if (Array.isArray(pkg.dependencyPaths) && pkg.dependencyPaths.length > MAX_PATHS) wasTruncated = true;
    for (const rawPath of paths) {
      if (typeof rawPath !== 'string' || rawPath.length > 4096) continue;
      const segments = rawPath.split(/\s*->\s*/);
      if (segments.length < 2 || segments.length > MAX_DEPTH) continue;
      const chain: DependencyGraphNode[] = [];
      let valid = true;
      for (const segment of segments) {
        const parsed = parseVersionedPathSegment(segment);
        if (!parsed) {
          valid = false;
          break;
        }
        const matches = candidates.get(`${pkg.ecosystem}:${parsed.name}@${parsed.version}`) ?? [];
        if (matches.length !== 1) {
          valid = false;
          break;
        }
        const matchedNode = nodeById.get(nodeId(matches[0]!));
        if (!matchedNode) {
          valid = false;
          break;
        }
        chain.push(matchedNode);
      }
      if (!valid) continue;

      for (let index = 0; index < chain.length - 1; index++) {
        const from = chain[index]!.id;
        const to = chain[index + 1]!.id;
        const key = `${from}\u0000${to}`;
        if (edgeKeys.has(key)) continue;
        if (edges.length >= MAX_EDGES) {
          wasTruncated = true;
          break;
        }
        edgeKeys.add(key);
        edges.push({ from, to });
      }
    }
  }

  const pathSearch = findVulnerablePaths(nodes, edges);
  return {
    nodes,
    edges,
    vulnerablePaths: pathSearch.paths,
    available: edges.length > 0,
    cycleDetected: detectCycle(nodes, edges),
    truncated: wasTruncated || pathSearch.truncated
  };
}
