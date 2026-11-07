export type ArtifactVisibility = "public" | "controlled" | "private";

export type ArtifactPhase = "foundation" | "access" | "operations";

export type ArtifactPlanItem = {
  name: string;
  visibility: ArtifactVisibility;
  phase: ArtifactPhase;
  format: string;
  rationale: string;
  groundedBy: string[];
};

export type RolloutPhase = {
  phase: ArtifactPhase;
  title: string;
  objective: string;
  items: string[];
};
