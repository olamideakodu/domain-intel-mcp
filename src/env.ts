export const ENV = {
  PORT: (() => {
    const raw = process.env.PORT ?? "3000";
    const parsed = Number(raw);
    if (Number.isNaN(parsed) || parsed <= 0 || parsed > 65535) {
      throw new Error(`Invalid PORT value: ${raw}`);
    }
    return parsed;
  })(),

  NODE_ENV: (() => {
    const env = process.env.NODE_ENV ?? "development";
    if (!["development", "production", "test"].includes(env)) {
      throw new Error(`Invalid NODE_ENV: ${env}`);
    }
    return env as "development" | "production" | "test";
  })(),
};
