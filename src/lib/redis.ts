import { Redis } from 'ioredis'

const url = process.env.REDIS_URL
if (!url) throw new Error('Missing REDIS_URL env var')

export const redis = new Redis(url, {
  maxRetriesPerRequest: 3,
  enableReadyCheck:     true,
  connectTimeout:       10000,
  retryStrategy: (times: number) => Math.min(times * 500, 30000),
})

export const bullRedis = new Redis(url, {
  maxRetriesPerRequest: null,
  enableReadyCheck:     false,
  connectTimeout:       10000,
  retryStrategy: (times: number) => Math.min(times * 500, 30000),
})

redis.on('connect',      () => console.log('[redis] connected'))
redis.on('error',        (err: Error) => console.error('[redis] error:', err.message))
redis.on('reconnecting', () => console.log('[redis] reconnecting...'))