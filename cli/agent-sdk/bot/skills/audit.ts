import { defineSkill } from "@grok/agent-sdk/skills";
import { workflowSkillConfig } from "../../lib/skills.js";

export default defineSkill(workflowSkillConfig("audit"));
