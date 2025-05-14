DROP DATABASE IF EXISTS home_service_hub;
CREATE DATABASE home_service_hub;

\c home_service_hub;

DROP TABLE IF EXISTS bookings;
DROP TABLE IF EXISTS services;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    reset_otp VARCHAR(6),
    reset_otp_expires TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE services (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE bookings (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    service_id INTEGER REFERENCES services(id),
    booking_date TIMESTAMP NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert some sample services
INSERT INTO services (name, description, price) VALUES
('Plumbing Service', 'Professional plumbing repairs and installations', 2500),
('Electrical Work', 'Electrical repairs and wiring services', 3000),
('House Cleaning', 'Complete house cleaning service', 4000),
('AC Repair', 'Air conditioner repair and maintenance', 3500),
('Painting Service', 'Interior and exterior painting', 15000);
