import type { Capability, ArtifactCategory, ToolCapabilitySpec } from "./types.js";
import { TOOL_SPECS, WORKFLOW_DEFINITIONS, KERNEL_TOOLS, type WorkflowDefinition } from "./capability-graph.js";

// ─── Progressive Disclosure ──────────────────────────────────────────────────
// Controls which tools are visible to the LLM at any given moment.
// Keeps context clean: max ~35-42 tools visible instead of 132.

export class ProgressiveDisclosure {
  private readonly activeWorkflows: Set<string> = new Set();
  private readonly toolsByWorkflow: ReadonlyMap<string, readonly ToolCapabilitySpec[]>;
  private onToolsChanged: (() => void) | null = null;

  constructor() {
    const map = new Map<string, ToolCapabilitySpec[]>();
    for (const spec of TOOL_SPECS) {
      const cat = spec.category as string;
      const existing = map.get(cat) ?? [];
      existing.push(spec);
      map.set(cat, existing);
    }
    this.toolsByWorkflow = map;
  }

  /** Register callback for tools/list_changed notification */
  setOnToolsChanged(cb: () => void): void {
    this.onToolsChanged = cb;
  }

  /** Get ALL tools (for --all-tools mode — capability kernel still guards execution) */
  getAllTools(): readonly ToolCapabilitySpec[] {
    return TOOL_SPECS;
  }

  /** Get currently visible tools (kernel + active workflows) */
  getVisibleTools(): readonly ToolCapabilitySpec[] {
    const visible: ToolCapabilitySpec[] = [];
    const kernelSet = new Set(KERNEL_TOOLS);

    // Always include kernel tools
    for (const spec of TOOL_SPECS) {
      if (kernelSet.has(spec.tool)) {
        visible.push(spec);
      }
    }

    // Include tools from active workflows (excluding duplicates from kernel)
    for (const workflowId of this.activeWorkflows) {
      const tools = this.toolsByWorkflow.get(workflowId) ?? [];
      for (const spec of tools) {
        if (!kernelSet.has(spec.tool)) {
          visible.push(spec);
        }
      }
    }

    return visible;
  }

  /** Activate a workflow — makes its tools visible */
  activate(workflowId: string): { success: boolean; message: string; newTools: readonly string[] } {
    const workflow = WORKFLOW_DEFINITIONS.find((w) => w.id === workflowId);
    if (!workflow) {
      return { success: false, message: `Unknown workflow "${workflowId}". Use list_workflows to see available workflows.`, newTools: [] };
    }

    if (this.activeWorkflows.has(workflowId)) {
      return { success: true, message: `Workflow "${workflow.name}" is already active.`, newTools: [] };
    }

    this.activeWorkflows.add(workflowId);
    const tools = (this.toolsByWorkflow.get(workflowId) ?? []).map((s) => s.tool);
    this.onToolsChanged?.();

    return { success: true, message: `Activated "${workflow.name}". ${tools.length} tools now available.`, newTools: tools };
  }

  /** Deactivate a workflow — hides its tools */
  deactivate(workflowId: string): { success: boolean; message: string } {
    if (!this.activeWorkflows.has(workflowId)) {
      return { success: true, message: `Workflow "${workflowId}" was not active.` };
    }

    this.activeWorkflows.delete(workflowId);
    this.onToolsChanged?.();

    const workflow = WORKFLOW_DEFINITIONS.find((w) => w.id === workflowId);
    return { success: true, message: `Deactivated "${workflow?.name ?? workflowId}". Tools hidden.` };
  }

  /** Check if a tool is currently visible */
  isToolVisible(tool: string): boolean {
    if (KERNEL_TOOLS.includes(tool)) return true;
    for (const workflowId of this.activeWorkflows) {
      const tools = this.toolsByWorkflow.get(workflowId) ?? [];
      if (tools.some((s) => s.tool === tool)) return true;
    }
    return false;
  }

  /** Auto-activate workflows when new capabilities are gained */
  onCapabilityGained(newCapabilities: readonly Capability[]): readonly string[] {
    const activated: string[] = [];
    for (const workflow of WORKFLOW_DEFINITIONS) {
      if (this.activeWorkflows.has(workflow.id)) continue;
      if (workflow.autoActivateOn.length === 0) continue;
      if (workflow.autoActivateOn.some((cap) => newCapabilities.includes(cap))) {
        this.activeWorkflows.add(workflow.id);
        activated.push(workflow.id);
      }
    }
    if (activated.length > 0) {
      this.onToolsChanged?.();
    }
    return activated;
  }

  /** Get all workflow definitions with current status */
  listWorkflows(heldCapabilities: readonly Capability[]): readonly (WorkflowDefinition & { active: boolean; available: boolean })[] {
    const heldSet = new Set(heldCapabilities);
    return WORKFLOW_DEFINITIONS.map((w) => ({
      ...w,
      active: this.activeWorkflows.has(w.id),
      available: w.prerequisites.every((cap) => heldSet.has(cap)),
    }));
  }

  /** Get currently active workflow IDs */
  getActiveWorkflows(): readonly string[] {
    return [...this.activeWorkflows];
  }

  /** Get count of currently visible tools */
  getVisibleToolCount(): number {
    return this.getVisibleTools().length;
  }

  /** Reset (for testing) */
  reset(): void {
    this.activeWorkflows.clear();
  }
}
