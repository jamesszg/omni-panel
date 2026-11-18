import { z } from 'zod';

export const ShadowtlsClientSchema = z.object({
  password: z.string().default(''),
  id: z.string().optional(),
  email: z.string().min(1),
  limitIp: z.number().int().min(0).default(0),
  totalGB: z.number().int().min(0).default(0),
  expiryTime: z.number().int().default(0),
  enable: z.boolean().default(true),
  tgId: z
    .union([z.number(), z.string()])
    .transform((v) => Number(v) || 0)
    .default(0),
  subId: z.string().default(''),
  comment: z.string().default(''),
  reset: z.number().int().min(0).default(0),
  created_at: z.number().int().optional(),
  updated_at: z.number().int().optional(),
});
export type ShadowtlsClient = z.infer<typeof ShadowtlsClientSchema>;

export const ShadowtlsInboundSettingsSchema = z.object({
  clients: z.array(ShadowtlsClientSchema).default([]),
  handshakeServer: z.string().default('www.microsoft.com'),
  handshakePort: z.number().int().min(1).max(65535).default(443),
  detour: z.string().default(''),
});
export type ShadowtlsInboundSettings = z.infer<typeof ShadowtlsInboundSettingsSchema>;
