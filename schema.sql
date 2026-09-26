-- Schéma D1 pour la persistance centrale des bilans de passage
-- (tous animateurs confondus) — alimente le futur dashboard d'analyse.

CREATE TABLE IF NOT EXISTS bilans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  magasin_code TEXT NOT NULL,
  magasin_libelle TEXT,
  ar TEXT,
  date TEXT NOT NULL,
  passage TEXT,
  humeur INTEGER,
  ca_mensuel TEXT,
  ca_annuel TEXT,
  renta TEXT,
  data_json TEXT NOT NULL,   -- objet collectData() complet, en JSON (actions, kpis, forts, diff, entretiens, etc.)
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_bilans_magasin ON bilans(magasin_code);
CREATE INDEX IF NOT EXISTS idx_bilans_ar ON bilans(ar);
CREATE INDEX IF NOT EXISTS idx_bilans_date ON bilans(date);

-- Fermetures réseau (26/09/2026) : Kippour ou toute fermeture de tous les magasins,
-- saisies dans import.html. Retirées des jours attendus de lancement de journée.
CREATE TABLE IF NOT EXISTS fermetures_reseau (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  intitule TEXT NOT NULL,
  date_debut TEXT NOT NULL,
  nb_jours INTEGER NOT NULL DEFAULT 1,
  created_at TEXT
);
