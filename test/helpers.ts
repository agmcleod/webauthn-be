import { INestApplication } from '@nestjs/common'
import { Test, TestingModule } from '@nestjs/testing'
import { Knex } from 'knex'
// import * as request from 'supertest'

import { AppModule } from '../src/app.module'
import { KnexService } from '../src/knex/knex.service'

export async function cleanDb(knex: Knex) {
  await knex('users').del()
}

export async function createTestingModule(): Promise<{
  app: INestApplication
  knexService: KnexService
}> {
  const moduleFixture: TestingModule = await Test.createTestingModule({
    imports: [AppModule],
  }).compile()

  const app = moduleFixture.createNestApplication()
  await app.init()

  const knexService = app.get(KnexService)

  return {
    app,
    knexService,
  }
}

// export async function loginBeforeRequest(
//   app: INestApplication,
//   knex: Knex,
// ): Promise<{ token: string; userId: number }> {
//   const bcryptService = new BcryptService()
//   const res = await knex('users')
//     .insert({
//       username: 'userfore2e',
//       password: await bcryptService.hashString('mypassword'),
//     })
//     .returning('*')

//   const response = await request(app.getHttpServer()).post('/auth/login').send({
//     username: 'userfore2e',
//     password: 'mypassword',
//   })

//   return { token: response.body.access_token, userId: res[0].id }
// }
