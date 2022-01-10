import { Injectable } from '@nestjs/common'

import { KnexService } from '../knex/knex.service'
import { User } from './dtos/user.dto'

@Injectable()
export class UsersService {
  constructor(private knexService: KnexService) {}

  async registerUser(username: string): Promise<number[]> {
    // will need to pass public key data here
    return this.knexService.knex('users').insert({
      username,
    })
  }

  async findByUsername(username: string): Promise<User | null> {
    return this.knexService
      .knex('users')
      .where({
        username,
      })
      .first()
  }
}
