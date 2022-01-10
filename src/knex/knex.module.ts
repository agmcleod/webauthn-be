import { Module, Global } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'

import { KnexService } from './knex.service'

@Global()
@Module({
  imports: [ConfigModule],
  providers: [KnexService],
  exports: [KnexService],
})
export class KnexModule {}
