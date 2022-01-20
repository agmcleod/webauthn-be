exports.up = function (knex) {
  return knex.schema.createTable('users', (table) => {
    table.increments('id')
    table.string('username').notNullable()
    table.string('cred_id').notNullable()
    table.string('public_key').notNullable()
    table.integer('counter').notNullable()
    table.timestamps(false, true)
  })
}

exports.down = function (knex) {
  return knex.schema.dropTable('users')
}
