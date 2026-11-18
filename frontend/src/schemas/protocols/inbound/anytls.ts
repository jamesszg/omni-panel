import { z } from 'zod';

export const AnytlsClientSchema = z.object({
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
export type AnytlsClient = z.infer<typeof AnytlsClientSchema>;

export const AnytlsInboundSettingsSchema = z.object({
  clients: z.array(AnytlsClientSchema).default([]),
  paddingScheme: z
    .array(z.string())
    .default([
      'stop=8',
      '0=30-30',
      '1=100-400',
      '2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000',
    ]),
});
export type AnytlsInboundSettings = z.infer<typeof AnytlsInboundSettingsSchema>;
