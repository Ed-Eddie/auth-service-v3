import 'dotenv/config'
import Fastify, { type FastifyError } from 'fastify'
import helmet    from '@fastify/helmet'
import cors      from '@fastify/cors'
import rateLimit from '@fastify/rate-limit'
import { authRoutes }  from './routes/auth.js'
import { adminRoutes } from './routes/admin.js'
import { userRoutes }  from './routes/user.js'
import { redis }       from './lib/redis.js'

const app = Fastify({
  logger: {
    level:  process.env.NODE_ENV === 'production' ? 'info' : 'debug',
    redact: ['req.headers.authorization'],
  },
  trustProxy:        true,
  connectionTimeout: 10000,
  requestTimeout:    30000,
})

await app.register(helmet, {
  contentSecurityPolicy:    false,
  crossOriginEmbedderPolicy: false,
})

const origins = (process.env.ALLOWED_ORIGINS ?? '').split(',').filter(Boolean)
await app.register(cors, {
  origin:      origins.length > 0 ? origins : true,
  methods:     ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  credentials: true,
})

await app.register(rateLimit, {
  global:     true,
  max:        100,
  timeWindow: '1 minute',
  keyGenerator: (req) => {
    const fwd = req.headers['x-forwarded-for']
    return typeof fwd === 'string' ? fwd.split(',')[0]!.trim() : req.ip ?? 'unknown'
  },
  errorResponseBuilder: (_req, context) => ({
    error:      `Too many requests. Retry after ${context.after}.`,
    statusCode: 429,
  }),
})

// Error and not-found handlers must be registered before routes in Fastify v5
app.setErrorHandler((error: FastifyError, req, reply) => {
  app.log.error({ err: error, url: req.url }, 'Unhandled error')
  if (error.validation) return reply.status(400).send({ error: 'Invalid request data' })
  if (error.statusCode) return reply.status(error.statusCode).send({ error: error.message })
  return reply.status(500).send({ error: 'Internal server error' })
})

app.setNotFoundHandler((_req, reply) => {
  reply.status(404).send({ error: 'Not found' })
})

await app.register(authRoutes)
await app.register(adminRoutes)
await app.register(userRoutes)

// Debug — list all registered routes on startup
app.ready(() => {
  console.log('[routes]', app.printRoutes())
})

const shutdown = async (signal: string) => {
  app.log.info(`${signal} — shutting down gracefully`)
  await app.close()
  await redis.quit()
  process.exit(0)
}

process.on('SIGTERM', () => shutdown('SIGTERM'))
process.on('SIGINT',  () => shutdown('SIGINT'))

async function start() {
  try {
    const port = parseInt(process.env.PORT ?? '3001')
    await app.listen({ port, host: '0.0.0.0' })
    app.log.info(`Auth service v2.0 running on port ${port}`)
  } catch (err: unknown) {
    app.log.error(err instanceof Error ? err.message : err)
    process.exit(1)
  }
}

start()