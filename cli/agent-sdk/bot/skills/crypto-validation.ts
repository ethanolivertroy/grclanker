import { defineSkill } from "@grok/agent-sdk/skills";
import { bundledSkillConfig } from "../../lib/skills.js";

export default defineSkill(bundledSkillConfig("crypto-validation"));
