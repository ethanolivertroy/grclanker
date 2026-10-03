import { defineSkill } from "@cursor/bdk/skills";
import { bundledSkillConfig } from "../../lib/skills.js";

export default defineSkill(bundledSkillConfig("crypto-validation"));
