package db

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

func ConnDB() error {

	db, err := sql.Open("sqlite3", "./cyberrange.db?_busy_timeout=5000")

	if err != nil {
		panic(err)
	}

	err = db.Ping()
	if err != nil {
		return err
	}

	DB = db

	err = createTables()
	if err != nil {
		return err
	}

	return nil
}

func createTables() error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        role TEXT NOT NULL,
        password TEXT NOT NULL,
        running_lab TEXT,
        attack_defense_role TEXT DEFAULT 'Out',
        otp TEXT
	);

    CREATE TABLE IF NOT EXISTS labs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        description TEXT NOT NULL,
        composefile TEXT NOT NULL,
        container_names TEXT[] NOT NULL,
        category TEXT NOT NULL,
        isctf TEXT NOT NULL,
        hidden TEXT NOT NULL DEFAULT 'false'
        );

	CREATE TABLE IF NOT EXISTS labs_solves (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT NOT NULL,
		lab_name TEXT NOT NULL,
		category TEXT NOT NULL,
		time TEXT NOT NULL
		);

	CREATE TABLE IF NOT EXISTS lab_categories (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE
		);

	CREATE TABLE IF NOT EXISTS ctf_challenges (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		description TEXT NOT NULL,
		flag TEXT NOT NULL,
		points INTEGER NOT NULL,
		category TEXT NOT NULL,
		difficulty TEXT NOT NULL,
		hint TEXT,
		attachments TEXT
	);

	CREATE TABLE IF NOT EXISTS ctf_solves (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name INTEGER NOT NULL,
		challenge_name TEXT NOT NULL,
		solve_date TEXT NOT NULL,
		points INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS flags (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT NOT NULL,
		flag TEXT NOT NULL UNIQUE,
		challenge_name TEXT NOT NULL
		);

	CREATE TABLE IF NOT EXISTS feedback (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		feedback TEXT NOT NULL,
		created_at TEXT NOT NULL,
		type TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS contactus (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		email TEXT NOT NULL,
		message TEXT NOT NULL
	);	`

	_, err := DB.Exec(query)
	if err != nil {
		return err
	}

	tableCheck := `SELECT name FROM sqlite_master WHERE type='table' AND name='ctf';`
	row := DB.QueryRow(tableCheck)
	var name string
	err = row.Scan(&name)

	if err == sql.ErrNoRows {
		query2 := `
			CREATE TABLE ctf (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				flag TEXT NOT NULL,
				status TEXT NOT NULL,
				set_for_release TEXT NOT NULL,
				release_date TEXT,
				type TEXT NOT NULL,
				docker_image TEXT DEFAULT 'none'
			);

			INSERT INTO ctf (flag, status, set_for_release, release_date,type) VALUES ('AUCYBERCTF{flag}', 'false', 'false', '', 'jeopardy');
			INSERT INTO ctf (flag, status, set_for_release, release_date,type) VALUES ('AUCYBERCTF{flag}', 'false', 'false', '', 'attack-defense');
			`
		_, err = DB.Exec(query2)
		if err != nil {
			return err
		}
	}

	return nil

}
