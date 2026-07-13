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
