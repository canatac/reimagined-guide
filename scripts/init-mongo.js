// Script d'initialisation MongoDB
// Crée automatiquement les collections nécessaires au démarrage

db = db.getSiblingDB('mailserver');

// Créer les collections avec validation de schéma
db.createCollection('users');
db.createCollection('emails');
db.createCollection('mailboxes');
db.createCollection('subscriptions');
db.createCollection('archive');

// Index sur les users
db.users.createIndex({ "username": 1 }, { unique: true });

// Index sur les emails
db.emails.createIndex({ "user_id": 1, "mailbox": 1 });
db.emails.createIndex({ "user_id": 1, "id": 1 });
db.emails.createIndex({ "user_id": 1, "flags": 1 });

// Index sur les mailboxes
db.mailboxes.createIndex({ "user_id": 1, "name": 1 }, { unique: true });

print('MongoDB initialization complete');
