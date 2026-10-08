import { defineSkill } from "@cursor/bdk/skills";
import { workflowSkillConfig } from "../../lib/skills.js";

export default defineSkill(workflowSkillConfig("assess"));
