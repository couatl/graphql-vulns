const express = require('express');
const fs = require('fs');
const expressJwt = require('express-jwt');
const jwt = require('jsonwebtoken');
const { ApolloServer } = require('apollo-server-express');

const { resolvers } = require('./resolvers');

const PORT = 4000;

// The GraphQL schema in string form
const schemaFile = fs.readFileSync('graphql/schema.graphql');
const typeDefs = schemaFile.toString();

const app = express();

const authMiddleware = expressJwt({
    secret: process.env.JWT_SECRET,
    algorithms: ["RS256"]
}).unless({
    path: [
        '/',
        '/graphql',
    ]
})

app.use(authMiddleware);

const server = new ApolloServer({
    typeDefs,
    resolvers,
    context: ({req}) => {
        const header = req.headers.authorization || '';
        let user;

        if (header) {
            const token = header.replace('Bearer ', '');

            user = jwt.verify(token, process.env.JWT_SECRET);
        }

        return { user };
    },
});

server.applyMiddleware({ app });

app.listen({ port: PORT }, () =>
    console.log(`🚀 Server ready at http://localhost:${PORT}${server.graphqlPath}`)
)