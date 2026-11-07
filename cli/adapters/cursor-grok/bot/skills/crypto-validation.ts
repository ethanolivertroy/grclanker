import { defineSkill } from "@grok/agent-sdk/skills";
import { bundledSkillConfig } from "../../../../core/skills.js";

export default defineSkill(bundledSkillConfig("crypto-validation"));
