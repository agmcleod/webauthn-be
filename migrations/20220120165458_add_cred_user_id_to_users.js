exports.up = function (knex) {
  return knex.schema.alterTable('users', (table) => {
    table.string('cred_user_id').notNullable()
  })
}

exports.down = function (knex) {
  return knex.schema.alterTable('users', (table) => {
    table.dropColumn('cred_user_id')
  })
}
