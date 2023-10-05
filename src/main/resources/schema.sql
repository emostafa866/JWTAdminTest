CREATE TABLE IF NOT EXISTS `admin` (
    `admin_id`         INTEGER  PRIMARY KEY AUTO_INCREMENT,
    `username` VARCHAR(150) NOT NULL,
    `password` VARCHAR(70) NOT NULL
);

CREATE TABLE IF NOT EXISTS `user` (
   `user_id`         INTEGER  PRIMARY KEY AUTO_INCREMENT,
   `username` VARCHAR(150) NOT NULL,
   `email` VARCHAR(250) NOT NULL
);
