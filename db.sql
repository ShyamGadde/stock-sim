CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    cash DECIMAL(10,2) NOT NULL DEFAULT 10000.00
);

CREATE TABLE IF NOT EXISTS portfolio (
    user_id INT NOT NULL,
    symbol VARCHAR(255) NOT NULL,
    quantity INT NOT NULL,
    PRIMARY KEY (user_id, symbol)
);

CREATE TABLE IF NOT EXISTS transactions (
    user_id INT NOT NULL,
    symbol VARCHAR(255) NOT NULL,
    quantity INT NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX username ON users (username);
