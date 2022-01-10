import { Injectable } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import knex, { Knex } from 'knex'

@Injectable()
export class KnexService {
  knex: Knex

  constructor(private config: ConfigService) {
    this.knex = knex({
      client: 'pg',
      connection: {
        host: config.get('DATABASE_HOST'),
        user: config.get('DATABASE_USERNAME'),
        database: config.get('DATABASE_NAME'),
      },
    })
  }

  async beforeApplicationShutdown() {
    await this.knex.destroy()
  }
}
