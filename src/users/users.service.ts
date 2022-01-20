import { Injectable } from '@nestjs/common'

import { KnexService } from '../knex/knex.service'
import { User } from './dtos/user.dto'

@Injectable()
export class UsersService {
  constructor(private knexService: KnexService) {}

  async registerUser(
    username: string,
    publicKey: string,
    counter: number,
    credId: string,
    credUserId: string,
  ): Promise<number[]> {
    // storing a single key here for an example, but should store multiple
    return this.knexService.knex('users').insert({
      username,
      public_key: publicKey,
      counter,
      cred_id: credId,
      cred_user_id: credUserId,
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
