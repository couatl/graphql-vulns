DROP TABLE IF EXISTS USERS;
DROP TABLE IF EXISTS PRODUCTS;
DROP TABLE IF EXISTS SHOPS;

CREATE TABLE USERS(ID SERIAL INTEGER PRIMARY KEY NOT NULL, NAME TEXT NOT NULL, EMAIL TEXT NOT NULL, PASSWORD TEXT NOT NULL);
CREATE TABLE PRODUCTS(ID SERIAL INTEGER PRIMARY KEY NOT NULL, NAME TEXT NOT NULL, SHOP_ID INTEGER);
CREATE TABLE USER_PRODUCTS(ID SERIAL INTEGER PRIMARY KEY NOT NULL, USER_ID INTEGER NOT NULL, PRODUCT_ID INTEGER NOT NULL);
CREATE TABLE SHOPS(ID SERIAL INTEGER PRIMARY KEY NOT NULL, NAME TEXT NOT NULL);

INSERT INTO USERS(ID, NAME, EMAIL, PASSWORD) VALUES (1, 'Alice', 'alice@mail.com', '$2b$10$SJa2pangrMHwIHZb.h3Rm.ev.7GvPYNcN37//XBQZwG0lZ/FdNWNu');
INSERT INTO USERS(ID, NAME, EMAIL, PASSWORD) VALUES (2, 'Bob', 'bob@mail.com', '$2b$10$SJa2pangrMHwIHZb.h3Rm.ev.7GvPYNcN37//XBQZwG0lZ/FdNWNu');
INSERT INTO USERS(ID, NAME, EMAIL, PASSWORD) VALUES (3, 'Maxime', 'maxime@mail.com', '$2b$10$SJa2pangrMHwIHZb.h3Rm.ev.7GvPYNcN37//XBQZwG0lZ/FdNWNu');
INSERT INTO USERS(ID, NAME, EMAIL, PASSWORD) VALUES (4, 'Julien', 'julien@mail.com', '$2b$10$SJa2pangrMHwIHZb.h3Rm.ev.7GvPYNcN37//XBQZwG0lZ/FdNWNu');

INSERT INTO SHOPS(ID, NAME) VALUES (1, 'Perekrestok');
INSERT INTO SHOPS(ID, NAME) VALUES (2, 'Pyaterochka');

INSERT INTO PRODUCTS(ID, NAME, SHOP_ID) VALUES (1, 'Unicorn', 1);
INSERT INTO PRODUCTS(ID, NAME, SHOP_ID) VALUES (2, 'Dog', 1);
INSERT INTO PRODUCTS(ID, NAME, SHOP_ID) VALUES (3, 'Pen', 2);
INSERT INTO PRODUCTS(ID, NAME, SHOP_ID) VALUES (4, 'Table', 2);
INSERT INTO PRODUCTS(ID, NAME, SHOP_ID) VALUES (5, 'Wallet', 2);
INSERT INTO PRODUCTS(ID, NAME, SHOP_ID) VALUES (6, 'Heinz', 1);

INSERT INTO USER_PRODUCTS(ID, USER_ID, PRODUCT_ID) VALUES (1, 1, 1);
INSERT INTO USER_PRODUCTS(ID, USER_ID, PRODUCT_ID) VALUES (2, 1, 3);
INSERT INTO USER_PRODUCTS(ID, USER_ID, PRODUCT_ID) VALUES (3, 2, 2);
INSERT INTO USER_PRODUCTS(ID, USER_ID, PRODUCT_ID) VALUES (4, 2, 4);
INSERT INTO USER_PRODUCTS(ID, USER_ID, PRODUCT_ID) VALUES (5, 3, 6);
INSERT INTO USER_PRODUCTS(ID, USER_ID, PRODUCT_ID) VALUES (6, 4, 1);
INSERT INTO USER_PRODUCTS(ID, USER_ID, PRODUCT_ID) VALUES (7, 4, 2);
INSERT INTO USER_PRODUCTS(ID, USER_ID, PRODUCT_ID) VALUES (8, 4, 4);
INSERT INTO USER_PRODUCTS(ID, USER_ID, PRODUCT_ID) VALUES (9, 4, 6);
