import { Module } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'

import { KnexModule } from './knex/knex.module'
import { UsersModule } from './users/users.module'

@Module({
  imports: [ConfigModule.forRoot(), KnexModule, UsersModule],
  controllers: [],
  providers: [],
})
export class AppModule {}
