export const AUTH_PROVIDERS = ['email', 'google', 'facebook'] as const;
export type AuthProvider = typeof AUTH_PROVIDERS[number];

export const USER_ROLES = ['user', 'admin'] as const;
export type UserRole = typeof USER_ROLES[number];