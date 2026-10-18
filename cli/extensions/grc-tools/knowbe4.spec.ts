// The account record is exported cut to these fields, each admin to its own list; certificate-shaped account fields are
// summarized as present with their length.
export const ACCOUNT_FIELDS: readonly string[] = [
  "name",
  "type",
  "domains",
  "subscription_level",
  "subscription_end_date",
  "number_of_seats",
  "current_risk_score",
];
export const ACCOUNT_ADMIN_FIELDS: readonly string[] = ["id", "first_name", "last_name", "email"];
// Free-form buckets on the user record that the assessments never read and that could carry anything an admin typed.
export const USER_FREE_FORM_FIELDS: readonly string[] = [
  "comment",
  "custom_field_1",
  "custom_field_2",
  "custom_field_3",
  "custom_field_4",
  "custom_date_1",
  "custom_date_2",
];
