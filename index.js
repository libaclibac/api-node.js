const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');

dotenv.config();

// Définir la connexion à la base de données
const pool = mysql.createPool({
    host: 'localhost', 
    user: 'admin',
    password: 'Passw0rd',
    database: 'api',
    port: 3306 
});

// Test de la connexion
async function testConnection() {
    try {
        const [rows] = await pool.query('SHOW TABLES');
        console.log('Tables in the database:', rows);
    } catch (error) {
        console.error('Database connection error:', error);
    }
}

// Appeler le test
testConnection();

/************************************************************************************** */

const app = express();
app.use(express.json()); // Pour traiter les requêtes JSON


//http://localhost:3000/auth/signup
app.post('/auth/signup', async (req, res) => {
    const { name, email, password, role } = req.body;

    try {
        // Hacher le mot de passe
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insérer l'utilisateur dans la base de données
        await pool.query(
            'INSERT INTO utilisateurs (name, email, password, role) VALUES (?, ?, ?, ?)',
            [name, email, hashedPassword, role]
        );

        res.status(201).json({ message: 'Utilisateur créé avec succès' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            res.status(400).json({ error: 'Email déjà utilisé' });
        } else {
            console.error(error);
            res.status(500).json({ error: 'Erreur lors de l\'inscription' });
        }
    }
});


//http://localhost:3000/auth/login
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Vérifier si l'utilisateur existe dans la base
        const [users] = await pool.query(
            'SELECT * FROM utilisateurs WHERE email = ?',
            [email]
        );

        if (users.length === 0) {
            return res.status(404).json({ error: 'Utilisateur non trouvé' });
        }

        const user = users[0];

        // Comparer le mot de passe fourni avec celui dans la base
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ error: 'Mot de passe incorrect' });
        }

        // Générer un token JWT
        const token = jwt.sign(
            { id: user.id, role: user.role }, // Payload du token
            process.env.JWT_SECRET, // Clé secrète pour signer le token
            { expiresIn: '1h' } // Durée de validité du token (1 heure ici)
        );

        res.json({ message: 'Connexion réussie', token }); // Répondre avec le token
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Erreur lors de la connexion' });
    }
});

const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1]; // Récupérer le token dans l'en-tête Authorization

    if (!token) {
        return res.status(401).json({ error: 'Token manquant' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET); // Vérifier le token
        req.user = decoded; // Ajouter les informations de l'utilisateur au request
        next(); // Passer à la route suivante
    } catch (error) {
        return res.status(401).json({ error: 'Token invalide' });
    }
};


app.get('/protected', authenticate, (req, res) => {
    res.json({ message: 'Accès autorisé', user: req.user });
});


//http://localhost:3000/sessions
app.post('/sessions', authenticate, async (req, res) => {
    const { title, date } = req.body;

    // Vérifier que l'utilisateur est un formateur
    if (req.user.role !== 'formateur') {
        return res.status(403).json({ error: 'Accès interdit, seul un formateur peut créer une session' });
    }

    try {
        // Insérer la session dans la base de données
        const [result] = await pool.query(
            'INSERT INTO sessions (title, date, formateur_id) VALUES (?, ?, ?)',
            [title, date, req.user.id]
        );

        res.status(201).json({ message: 'Session créée avec succès', sessionId: result.insertId });
    } catch (error) {
        console.error('Erreur lors de la création de la session :', error);
        res.status(500).json({ error: 'Erreur lors de la création de la session' });
    }
});


//http://localhost:3000/sessions
app.get('/sessions', authenticate, async (req, res) => {
    try {
        const [sessions] = await pool.query('SELECT * FROM sessions');

        res.json({ sessions }); 
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Erreur lors de la récupération des sessions' });
    }
});


//http://localhost:3000/sessions/1
app.get('/sessions/:id', authenticate, async (req, res) => {
    const sessionId = req.params.id; // Récupérer l'ID de la session depuis les paramètres de l'URL

    try {
        // Requête pour récupérer les détails de la session
        const [session] = await pool.query('SELECT * FROM sessions WHERE id = ?', [sessionId]);

        if (session.length === 0) {
            return res.status(404).json({ error: 'Session non trouvée' });
        }

        // Retourner les détails de la session
        res.json({ session: session[0] }); // session[0] car le résultat est un tableau
    } catch (error) {
        console.error('Erreur lors de la récupération de la session :', error);
        res.status(500).json({ error: 'Erreur lors de la récupération des détails de la session' });
    }
});


//http://localhost:3000/sessions/1
app.put('/sessions/:id', authenticate, async (req, res) => {
    const sessionId = req.params.id; // Récupérer l'ID de la session à partir des paramètres de l'URL
    const { title, date } = req.body; // Récupérer les nouvelles données de la session

    // Vérifier que l'utilisateur est un formateur
    if (req.user.role !== 'formateur') {
        return res.status(403).json({ error: 'Accès interdit, seul un formateur peut modifier une session' });
    }

    try {
        // Vérifier si la session existe
        const [session] = await pool.query('SELECT * FROM sessions WHERE id = ?', [sessionId]);

        if (session.length === 0) {
            return res.status(404).json({ error: 'Session non trouvée' });
        }

        // Modifier la session dans la base de données
        await pool.query(
            'UPDATE sessions SET title = ?, date = ? WHERE id = ?',
            [title, date, sessionId]
        );

        res.json({ message: 'Session modifiée avec succès' });
    } catch (error) {
        console.error('Erreur lors de la modification de la session :', error);
        res.status(500).json({ error: 'Erreur lors de la modification de la session' });
    }
});


//http://localhost:3000/sessions/1
app.delete('/sessions/:id', authenticate, async (req, res) => {
    const sessionId = req.params.id; // Récupérer l'ID de la session à partir des paramètres de l'URL

    // Vérifier que l'utilisateur est un formateur
    if (req.user.role !== 'formateur') {
        return res.status(403).json({ error: 'Accès interdit, seul un formateur peut supprimer une session' });
    }

    try {
        // Vérifier si la session existe
        const [session] = await pool.query('SELECT * FROM sessions WHERE id = ?', [sessionId]);

        if (session.length === 0) {
            return res.status(404).json({ error: 'Session non trouvée' });
        }

        // Supprimer la session dans la base de données
        await pool.query('DELETE FROM sessions WHERE id = ?', [sessionId]);

        res.json({ message: 'Session supprimée avec succès' });
    } catch (error) {
        console.error('Erreur lors de la suppression de la session :', error);
        res.status(500).json({ error: 'Erreur lors de la suppression de la session' });
    }
});


//http://localhost:3000/sessions/1/emargement
app.post('/sessions/:id/emargement', authenticate, async (req, res) => {
    const sessionId = req.params.id; // Récupérer l'ID de la session depuis les paramètres de l'URL

    // Vérifier que l'utilisateur est un étudiant
    if (req.user.role !== 'etudiant') {
        return res.status(403).json({ error: 'Accès interdit, seul un étudiant peut s\'émarger à une session' });
    }

    try {
        // Vérifier si la session existe
        const [session] = await pool.query('SELECT * FROM sessions WHERE id = ?', [sessionId]);

        if (session.length === 0) {
            return res.status(404).json({ error: 'Session non trouvée' });
        }

        // Vérifier si l'étudiant s'est déjà émargé à cette session
        const [existingEmargement] = await pool.query('SELECT * FROM emargements WHERE session_id = ? AND etudiant_id = ?', [sessionId, req.user.id]);

        if (existingEmargement.length > 0) {
            return res.status(400).json({ error: 'Vous êtes déjà émargé à cette session' });
        }

        // Ajouter l'émargement dans la base de données avec un statut par défaut
        await pool.query(
            'INSERT INTO emargements (session_id, etudiant_id, status) VALUES (?, ?, ?)',
            [sessionId, req.user.id, 'emargé']
        );


        res.status(201).json({ message: 'Émargement effectué avec succès' });
    } catch (error) {
        console.error('Erreur lors de l\'émargement à la session :', error);
        res.status(500).json({ error: 'Erreur lors de l\'émargement' });
    }
});


//http://localhost:3000/sessions/1/emargement
app.get('/sessions/:id/emargement', authenticate, async (req, res) => {
    const sessionId = req.params.id; // Récupérer l'ID de la session depuis les paramètres de l'URL

    // Vérifier que l'utilisateur est un formateur
    if (req.user.role !== 'formateur') {
        return res.status(403).json({ error: 'Accès interdit, seul un formateur peut voir la liste des étudiants émargés' });
    }

    try {
        // Vérifier si la session existe
        const [session] = await pool.query('SELECT * FROM sessions WHERE id = ?', [sessionId]);

        if (session.length === 0) {
            return res.status(404).json({ error: 'Session non trouvée' });
        }

        // Récupérer la liste des étudiants émargés pour cette session
        const [emargements] = await pool.query(
            'SELECT u.id, u.name, u.email FROM emargements e INNER JOIN utilisateurs u ON e.etudiant_id = u.id WHERE e.session_id = ?',
            [sessionId]
        );

        // Si aucun étudiant n'est émargé, renvoyer un message approprié
        if (emargements.length === 0) {
            return res.status(404).json({ error: 'Aucun étudiant n\'est émargé à cette session' });
        }

        // Renvoyer la liste des étudiants émargés
        res.json({ emargements });
    } catch (error) {
        console.error('Erreur lors de la récupération des étudiants émargés :', error);
        res.status(500).json({ error: 'Erreur lors de la récupération des étudiants émargés' });
    }
});


const PORT = 3000;
app.listen(PORT, () => console.log(`Serveur démarré sur le port ${PORT}`));