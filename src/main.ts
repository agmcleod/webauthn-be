import { NestFactory } from '@nestjs/core'
import { ValidationPipe } from '@nestjs/common'
import * as session from 'express-session'

import { AppModule } from './app.module'

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    cors: {
      origin: 'http://localhost:3000',
      credentials: true,
      methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'],
      allowedHeaders: ['Content-Type', 'Authorization', '*'],
    },
  })
  app.useGlobalPipes(new ValidationPipe())
  app.use(
    session({
      secret: process.env.SESSION_KEY,
      resave: false,
      saveUninitialized: false,
    }),
  )
  await app.listen(8080)
}
bootstrap()
