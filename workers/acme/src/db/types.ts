import type * as schema from "./schema";

export type AccountRow = typeof schema.accounts.$inferSelect;
export type AccountInsert = typeof schema.accounts.$inferInsert;
export type AccountKeyConflictRow = typeof schema.accountKeyConflicts.$inferSelect;
export type AccountKeyConflictInsert = typeof schema.accountKeyConflicts.$inferInsert;
export type OrderRow = typeof schema.orders.$inferSelect;
export type OrderInsert = typeof schema.orders.$inferInsert;
export type AuthorizationRow = typeof schema.authorizations.$inferSelect;
export type AuthorizationInsert = typeof schema.authorizations.$inferInsert;
export type ChallengeRow = typeof schema.challenges.$inferSelect;
export type ChallengeInsert = typeof schema.challenges.$inferInsert;
export type ChallengeType = ChallengeRow["type"];
export type ChallengeStatus = ChallengeRow["status"];
export type CertificateRow = typeof schema.certificates.$inferSelect;
export type CertificateInsert = typeof schema.certificates.$inferInsert;
export type NonceRow = typeof schema.nonces.$inferSelect;
export type RateLimitRow = typeof schema.rateLimits.$inferSelect;
