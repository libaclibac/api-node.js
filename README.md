# api-node.js

docker run -p 3306:3306 `
  -e MYSQL_ROOT_PASSWORD=Passw0rd `
  -e MYSQL_USER=admin `
  -e MYSQL_DATABASE=api `
  -e MYSQL_PASSWORD=Passw0rd `
  -d mysql


docker exec -it <CONTAINER_ID> mysql -uadmin -p


-- Table des utilisateurs
CREATE TABLE utilisateurs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role ENUM('formateur', 'etudiant') NOT NULL
);

-- Table des sessions
CREATE TABLE sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(100) NOT NULL,
    date DATE NOT NULL,
    formateur_id INT NOT NULL,
    FOREIGN KEY (formateur_id) REFERENCES utilisateurs(id) ON DELETE CASCADE
);

-- Table des émargements
CREATE TABLE emargements (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id INT NOT NULL,
    etudiant_id INT NOT NULL,
    status BOOLEAN NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
    FOREIGN KEY (etudiant_id) REFERENCES utilisateurs(id) ON DELETE CASCADE
);

ALTER TABLE emargements MODIFY COLUMN status VARCHAR(50) DEFAULT 'emargé';
