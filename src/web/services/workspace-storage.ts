const STORAGE_KEY = 'veylix_workspace_v1';
const MAX_PROJECTS = 50;

export interface LocalWorkspaceProject {
  id: string;
  name: string;
  createdAt: string;
}

export interface LocalWorkspace {
  projects: LocalWorkspaceProject[];
  scanProjects: Record<string, string>;
  baselines: Record<string, string>;
}

const EMPTY_WORKSPACE: LocalWorkspace = { projects: [], scanProjects: {}, baselines: {} };

function isWorkspace(value: unknown): value is LocalWorkspace {
  if (!value || typeof value !== 'object') return false;
  const workspace = value as Partial<LocalWorkspace>;
  const projects = workspace.projects;
  const projectsValid = Array.isArray(projects) &&
    projects.length <= MAX_PROJECTS &&
    projects.every((project) => Boolean(
      project &&
      typeof project.id === 'string' &&
      project.id.length <= 100 &&
      typeof project.name === 'string' &&
      project.name.trim().length > 0 &&
      project.name.length <= 100 &&
      typeof project.createdAt === 'string' &&
      Number.isFinite(Date.parse(project.createdAt))
    )) &&
    new Set(projects.map((project) => project.id)).size === projects.length;
  const mapsValid = (map: unknown): map is Record<string, string> =>
    Boolean(map && typeof map === 'object' && !Array.isArray(map)) &&
    Object.entries(map as Record<string, unknown>).length <= 1_000 &&
    Object.entries(map as Record<string, unknown>).every(([key, item]) =>
      key.length > 0 && key.length <= 100 && typeof item === 'string' && item.length <= 100
    );
  return projectsValid && mapsValid(workspace.scanProjects) && mapsValid(workspace.baselines);
}

export function loadLocalWorkspace(): LocalWorkspace {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return EMPTY_WORKSPACE;
    const parsed: unknown = JSON.parse(raw);
    if (isWorkspace(parsed)) return parsed;
    console.warn('Saved local workspace data was invalid and has been skipped.');
    return EMPTY_WORKSPACE;
  } catch (error) {
    console.warn('Failed to load local workspace data:', error);
    return EMPTY_WORKSPACE;
  }
}

function persist(workspace: LocalWorkspace): boolean {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(workspace));
    return true;
  } catch (error) {
    console.warn('Failed to save local workspace data:', error);
    return false;
  }
}

export function createLocalWorkspaceProject(name: string): { success: boolean; workspace: LocalWorkspace; error?: string } {
  const normalized = name.trim();
  if (normalized.length < 1 || normalized.length > 100) {
    return { success: false, workspace: loadLocalWorkspace(), error: 'Project name must be between 1 and 100 characters.' };
  }
  const workspace = loadLocalWorkspace();
  if (workspace.projects.length >= MAX_PROJECTS) {
    return { success: false, workspace, error: `A maximum of ${MAX_PROJECTS} local projects is supported.` };
  }
  if (workspace.projects.some((project) => project.name.toLowerCase() === normalized.toLowerCase())) {
    return { success: false, workspace, error: 'A project with this name already exists.' };
  }
  const project: LocalWorkspaceProject = {
    id: `project_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    name: normalized,
    createdAt: new Date().toISOString()
  };
  const updated = { ...workspace, projects: [project, ...workspace.projects] };
  return persist(updated)
    ? { success: true, workspace: updated }
    : { success: false, workspace, error: 'Could not save this project in browser storage.' };
}

export function assignScanToProject(
  scanId: string,
  projectId?: string
): { success: boolean; workspace: LocalWorkspace; error?: string } {
  const workspace = loadLocalWorkspace();
  if (!scanId || scanId.length > 100) {
    return { success: false, workspace, error: 'Scan identifier is invalid.' };
  }
  if (projectId && !workspace.projects.some((project) => project.id === projectId)) {
    return { success: false, workspace, error: 'Selected local project no longer exists.' };
  }
  const scanProjects = { ...workspace.scanProjects };
  if (projectId) scanProjects[scanId] = projectId;
  else delete scanProjects[scanId];
  const updated = { ...workspace, scanProjects };
  return persist(updated)
    ? { success: true, workspace: updated }
    : { success: false, workspace, error: 'Could not update this scan assignment in browser storage.' };
}

export function setProjectBaseline(
  projectId: string,
  scanId: string
): { success: boolean; workspace: LocalWorkspace; error?: string } {
  const workspace = loadLocalWorkspace();
  if (!workspace.projects.some((project) => project.id === projectId)) {
    return { success: false, workspace, error: 'Selected local project no longer exists.' };
  }
  if (workspace.scanProjects[scanId] !== projectId) {
    return { success: false, workspace, error: 'Baseline scan must be assigned to this project first.' };
  }
  const updated = { ...workspace, baselines: { ...workspace.baselines, [projectId]: scanId } };
  return persist(updated)
    ? { success: true, workspace: updated }
    : { success: false, workspace, error: 'Could not save this project baseline in browser storage.' };
}

export function removeScanFromWorkspace(scanId: string): boolean {
  const workspace = loadLocalWorkspace();
  const scanProjects = { ...workspace.scanProjects };
  delete scanProjects[scanId];
  const baselines = Object.fromEntries(
    Object.entries(workspace.baselines).filter(([, baselineScanId]) => baselineScanId !== scanId)
  );
  return persist({ ...workspace, scanProjects, baselines });
}

export function deleteLocalWorkspaceProject(projectId: string): { success: boolean; workspace: LocalWorkspace } {
  const workspace = loadLocalWorkspace();
  const scanProjects = Object.fromEntries(
    Object.entries(workspace.scanProjects).filter(([, assignedId]) => assignedId !== projectId)
  );
  const baselines = { ...workspace.baselines };
  delete baselines[projectId];
  const updated = {
    projects: workspace.projects.filter((project) => project.id !== projectId),
    scanProjects,
    baselines
  };
  return { success: persist(updated), workspace: updated };
}

export function clearLocalWorkspace(): boolean {
  try {
    localStorage.removeItem(STORAGE_KEY);
    return true;
  } catch (error) {
    console.warn('Failed to clear local workspace data:', error);
    return false;
  }
}
