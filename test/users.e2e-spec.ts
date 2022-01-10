import { INestApplication } from '@nestjs/common'
import * as request from 'supertest'

import { createTestingModule } from './helpers'

describe('Users (e2e)', () => {
  let app: INestApplication

  beforeAll(async () => {
    const ref = await createTestingModule()
    app = ref.app
  })

  afterAll(async () => {
    await app.close()
  })

  it('returns a challenge', async () => {
    return request(app.getHttpServer())
      .get('/users/challenge')
      .expect(200)
      .then((res) => {
        expect(res.body.id).toBeTruthy()
        expect(res.body.challenge).toBeTruthy()
      })
  })
})
