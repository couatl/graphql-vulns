const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const saltRounds = 10;

const knex = require('knex')({
    client: process.env.DB_CONNECTOR,
    connection: {
        host: process.env.DB_HOST,
        port: Number(process.env.DB_PORT),
        user: process.env.DB_USER,
        password: process.env.DB_PASS,
        database: process.env.DB_PRIMARY_DB,
    },
});

const resolvers = {
    Query: {
        products: async () => {
            return knex.select().from('products');
        },
        searchProducts: async (_, { namePrefix }) => {
            // [VULN]: There is a SQL injection vulnerability

            const result = await knex.raw(`select * from products where name like '${namePrefix}'`);

            return result.rows;
        },
        myProducts: async (_, { userId }, context) => {
            // [VULN]: There is vulnerability because of lack of authorization check

            const products = await knex('products')
                .join('user_products', 'products.id', 'user_products.product_id')
                .select()
                .where('user_products.user_id', userId);

            return {
                statusCode: 200,
                products
            };
        },
        userInfo: async (_, { userId }, context) => {
            if (!context.user) {
                return {
                    statusCode: 401,
                    message: 'Not authorized'
                };
            }

            if (context.user.id !== userId) {
                return {
                    statusCode: 401,
                    message: 'Incorrect credentials'
                };
            }

            const user = await knex.select().from('users').where('userid', userId);

            return {
                statusCode: 200,
                user
            };
        },
    },
    Mutation: {
        createProduct: async (_, { name, shopId }) => {
            const [createdProduct] = await knex('products').returning(['id', 'name']).insert({
                name,
                shop_id: shopId
            });

            return createdProduct;
        },
        addToMyProducts: async (_, { id, userId }, context) => {
            // [VULN]: There is vulnerability because of lack of authorization check

            await knex('user_products').insert({
               user_id: userId,
               product_id: id
            });

            return {
                statusCode: 200
            };
        },
        deleteFromMyProducts: async (_, { id, userId }, context) => {
            if (!context.user) {
                return {
                    statusCode: 401,
                    message: 'Not authorized'
                };
            }

            if (context.user.id !== userId) {
                return {
                    statusCode: 401,
                    message: 'Wrong credentials'
                };
            }

            await knex('user_products').del().where({
                user_id: userId,
                product_id: id
            });

            return {
                statusCode: 200
            };
        },
        createUser: async (_, { input }) => {
            const localUser = input;
            localUser.password = await bcrypt.hash(localUser.password, saltRounds);
            const [createdUser] = await knex('users').returning(['id', 'name', 'email']).insert(localUser);
            const signedJWT = await jwt.sign({
                userid: createdUser.id,
                email: createdUser.email,
                scope: {
                    dashboard: true,
                },
            }, process.env.JWT_SECRET, { expiresIn: '1h' });

            return {
                token: signedJWT,
                user: createdUser,
            };
        },
        loginUser: async (_, { input }) => {
            const [foundUser] = await knex('users').where('email', input.email);

            if (foundUser) {
                if (await bcrypt.compare(input.password, foundUser.password)) {
                    const signedJWT = await jwt.sign({
                        userid: foundUser.id,
                        email: foundUser.email,
                        scope: {
                            dashboard: true,
                        },
                    }, process.env.JWT_SECRET, { expiresIn: '1h' });

                    return {
                        token: signedJWT,
                        statusCode: 200,
                        user: {
                            id: foundUser.id,
                            email: foundUser.email,
                            name: foundUser.name
                        }
                    };
                }

                return {
                    statusCode: 401,
                    message: 'Incorrect credentials, please try again.',
                };
            }

            if (foundUser === undefined) {
                return {
                    statusCode: 401,
                    message: 'No User Account found with that email.',
                };
            }

            return {
                statusCode: 500,
                message: 'The server encountered an error, please try again!',
            };
        },
    },
};

module.exports = { resolvers };